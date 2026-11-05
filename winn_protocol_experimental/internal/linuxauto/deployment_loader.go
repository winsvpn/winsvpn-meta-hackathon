package linuxauto

import (
	"errors"
	"fmt"
	"time"

	"winsvpn.local/winnprotocol/internal/directawg"
	"winsvpn.local/winnprotocol/internal/gatewaymanifest"
	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/preparation"
	"winsvpn.local/winnprotocol/internal/securefile"
)

type VerifiedAutoDeploymentConfig struct {
	ManifestPath     string
	NodeID           string
	TransparencyLog  string
	TrustStatePath   string
	LinuxProfilePath string
	ControllerPins   *pqauth.VerifierSet
	Now              func() time.Time
}

// VerifiedAutoDeployment contains only outputs of the signature,
// transparency, rollback, typed-manifest, and signed Linux-profile verifiers.
// NextTrustState is not persisted until CommitTrustState is called after the
// selected deployment has been successfully prepared.
type VerifiedAutoDeployment struct {
	Manifest          gatewaymanifest.ManifestV2
	Node              gatewaymanifest.NodeV2
	ManifestDigest    string
	NextTrustState    gatewaymanifest.TrustStateV2
	Deployment        preparation.VerifiedDeploymentV2
	LinuxInterface    directawg.LinuxSignedInterfaceConfig
	LinuxVerification directawg.LinuxVerificationConfig

	trustStatePath string
}

func LoadVerifiedAutoDeployment(
	config VerifiedAutoDeploymentConfig,
) (VerifiedAutoDeployment, error) {
	if config.ManifestPath == "" ||
		config.NodeID == "" ||
		config.TransparencyLog == "" ||
		config.TrustStatePath == "" ||
		config.LinuxProfilePath == "" ||
		config.ControllerPins == nil {
		return VerifiedAutoDeployment{},
			errors.New(
				"verified Linux Auto deployment paths and pins are required",
			)
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	now := config.Now().UTC()
	manifest, node, digest, next, err :=
		gatewaymanifest.LoadVerifiedNodeV2(
			config.ManifestPath,
			config.NodeID,
			config.TransparencyLog,
			config.TrustStatePath,
			config.ControllerPins,
			now,
		)
	if err != nil {
		return VerifiedAutoDeployment{},
			fmt.Errorf("load verified Linux Auto manifest: %w", err)
	}
	deployment, err := preparation.BindVerifiedDeploymentV2(
		manifest, node, digest,
	)
	if err != nil {
		return VerifiedAutoDeployment{},
			fmt.Errorf("bind verified Linux Auto node: %w", err)
	}
	profile, err := directawg.LoadLinuxDeploymentProfile(
		config.LinuxProfilePath,
	)
	if err != nil {
		return VerifiedAutoDeployment{},
			fmt.Errorf("load signed Linux Auto profile: %w", err)
	}
	if profile.NodeID != node.ID {
		return VerifiedAutoDeployment{},
			errors.New(
				"signed Linux Auto profile selects a different verified node",
			)
	}
	interfaceConfig, verificationConfig, err :=
		directawg.VerifyLinuxDeploymentProfile(
			profile, manifest, config.ControllerPins, now,
		)
	if err != nil {
		return VerifiedAutoDeployment{},
			fmt.Errorf("verify signed Linux Auto profile: %w", err)
	}
	return VerifiedAutoDeployment{
		Manifest:          manifest,
		Node:              node,
		ManifestDigest:    digest,
		NextTrustState:    next,
		Deployment:        deployment,
		LinuxInterface:    interfaceConfig,
		LinuxVerification: verificationConfig,
		trustStatePath:    config.TrustStatePath,
	}, nil
}

// CommitTrustState atomically advances the rollback/transparency pin. The
// production driver calls this only after verified preparation succeeds.
func (deployment VerifiedAutoDeployment) CommitTrustState() error {
	if deployment.trustStatePath == "" {
		return errors.New(
			"verified Linux Auto trust-state destination is unavailable",
		)
	}
	encoded, err := gatewaymanifest.EncodeTrustStateV2(
		deployment.NextTrustState,
	)
	if err != nil {
		return err
	}
	defer clear(encoded)
	if err := securefile.AtomicWrite(
		deployment.trustStatePath, encoded, 0o600,
	); err != nil {
		return fmt.Errorf(
			"commit verified Linux Auto trust state: %w", err,
		)
	}
	return nil
}
