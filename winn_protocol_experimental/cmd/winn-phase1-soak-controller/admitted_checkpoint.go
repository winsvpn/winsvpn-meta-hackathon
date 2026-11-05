package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

const admittedCheckpointMACDomain = "winn-phase1-admitted-checkpoint-mac/v1\x00"

type admittedCheckpointEnvelope struct {
	Schema         string             `json:"schema"`
	Body           admittedCheckpoint `json:"body"`
	ContentAddress string             `json:"content_address"`
	MAC            string             `json:"mac"`
}

type admittedCheckpointStore struct {
	directory     *secureDirectory
	key           []byte
	ownsDirectory bool
}

func openAdmittedCheckpointStore(root string, create bool) (*admittedCheckpointStore, error) {
	directory, err := openAdmittedPrivateDirectory(root)
	if err != nil {
		return nil, err
	}
	if err := verifyAdmittedDirectoryPath(directory); err != nil {
		_ = directory.Close()
		return nil, err
	}
	store, err := openAdmittedCheckpointStoreDirectory(directory, create)
	if err != nil {
		_ = directory.Close()
		return nil, err
	}
	store.ownsDirectory = true
	return store, nil
}

func openAdmittedCheckpointStoreDirectory(
	directory *secureDirectory, create bool,
) (*admittedCheckpointStore, error) {
	keyFile, err := openAdmittedPrivateFile(
		directory, admittedCheckpointKeyFile, os.O_RDONLY, 0,
	)
	if errors.Is(err, os.ErrNotExist) && create {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		if err := atomicWriteAdmittedDirectory(
			directory, admittedCheckpointKeyFile, []byte(hex.EncodeToString(key)),
		); err != nil {
			return nil, err
		}
		return &admittedCheckpointStore{directory: directory, key: key}, nil
	}
	if err != nil {
		return nil, err
	}
	raw, readErr := io.ReadAll(io.LimitReader(keyFile, 65))
	closeErr := keyFile.Close()
	if readErr != nil || closeErr != nil || len(raw) != 64 {
		return nil, errors.New("admitted checkpoint key is invalid")
	}
	key, err := hex.DecodeString(string(raw))
	if err != nil || len(key) != 32 {
		return nil, errors.New("admitted checkpoint key is malformed")
	}
	return &admittedCheckpointStore{directory: directory, key: key}, nil
}

func (s *admittedCheckpointStore) Close() error {
	if s == nil || s.directory == nil {
		return nil
	}
	for index := range s.key {
		s.key[index] = 0
	}
	var err error
	if s.ownsDirectory {
		err = s.directory.Close()
	}
	s.directory = nil
	return err
}

func (s *admittedCheckpointStore) mac(address string) string {
	value := hmac.New(sha256.New, s.key)
	_, _ = value.Write([]byte(admittedCheckpointMACDomain))
	_, _ = value.Write([]byte(address))
	return hex.EncodeToString(value.Sum(nil))
}

func validateAdmittedCheckpoint(value admittedCheckpoint) error {
	digest := value.ObjectDigest
	value.ObjectDigest = ""
	expected, err := admittedDigest(admittedCheckpointDomain, value)
	if err != nil || digest != expected {
		return errors.New("admitted checkpoint object digest mismatch")
	}
	if value.Schema != admittedCheckpointSchema ||
		value.Mode != admittedMode || value.RunID == "" ||
		value.NextSequence != value.ReceiptCount+1 ||
		value.MatrixCyclesExecuted != 0 || value.HandoffReady ||
		value.DispatchAuthorized || value.ExternalTopologyExecuted ||
		value.ProviderAccess || value.CredentialAccess || value.Authority ||
		!noncePattern.MatchString(value.InstanceNonce) ||
		(value.PredecessorNonce != "" &&
			!noncePattern.MatchString(value.PredecessorNonce)) {
		return errors.New("admitted checkpoint fields are invalid")
	}
	for _, digest := range []string{
		value.ControllerConfigSHA256, value.LastReceiptDigest,
		value.ReceiptCollectionDigest, value.LastBindingDigest,
		value.LastIntentDigest, value.LastResultSHA256,
		value.AttemptInventoryDigest, digest,
	} {
		if !digestPattern.MatchString(digest) {
			return errors.New("admitted checkpoint digest is malformed")
		}
	}
	return nil
}

func (s *admittedCheckpointStore) Save(value admittedCheckpoint) (string, error) {
	value.Schema = admittedCheckpointSchema
	value.Mode = admittedMode
	value.ObjectDigest = ""
	digest, err := admittedDigest(admittedCheckpointDomain, value)
	if err != nil {
		return "", err
	}
	value.ObjectDigest = digest
	if err := validateAdmittedCheckpoint(value); err != nil {
		return "", err
	}
	body, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	address := admittedRawSHA(body)
	envelope := admittedCheckpointEnvelope{
		Schema: admittedCheckpointSchema, Body: value,
		ContentAddress: address, MAC: s.mac(address),
	}
	encoded, err := json.Marshal(envelope)
	if err != nil || len(encoded) > admittedMaximumObjectBytes {
		return "", errors.New("admitted checkpoint envelope exceeds bound")
	}
	if err := atomicWriteAdmittedDirectory(
		s.directory, admittedCheckpointFile, encoded,
	); err != nil {
		return "", err
	}
	replayed, replayedAddress, err := s.Load()
	if err != nil || replayed.ObjectDigest != value.ObjectDigest ||
		replayedAddress != address {
		return "", errors.New("admitted checkpoint durable replay mismatch")
	}
	return address, nil
}

func (s *admittedCheckpointStore) Load() (admittedCheckpoint, string, error) {
	file, err := openAdmittedPrivateFile(
		s.directory, admittedCheckpointFile, os.O_RDONLY, 0,
	)
	if errors.Is(err, os.ErrNotExist) {
		return admittedCheckpoint{}, "", errNoCheckpoint
	}
	if err != nil {
		return admittedCheckpoint{}, "", err
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, admittedMaximumObjectBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(raw) > admittedMaximumObjectBytes {
		return admittedCheckpoint{}, "", errors.New("read admitted checkpoint")
	}
	var envelope admittedCheckpointEnvelope
	if err := decodeStrictObject(raw, &envelope); err != nil {
		return admittedCheckpoint{}, "", err
	}
	body, err := json.Marshal(envelope.Body)
	if err != nil {
		return admittedCheckpoint{}, "", err
	}
	address := admittedRawSHA(body)
	if envelope.Schema != admittedCheckpointSchema ||
		envelope.ContentAddress != address ||
		!hmac.Equal([]byte(envelope.MAC), []byte(s.mac(address))) {
		return admittedCheckpoint{}, "", errors.New(
			"admitted checkpoint authentication failed",
		)
	}
	if err := validateAdmittedCheckpoint(envelope.Body); err != nil {
		return admittedCheckpoint{}, "", err
	}
	return envelope.Body, address, nil
}

func admittedCheckpointFrom(
	cfg AdmittedConfig,
	configDigest, nonce, predecessor, inventoryDigest string,
	log *admittedReceiptLog,
) (admittedCheckpoint, error) {
	if log.last == nil || log.count == 0 {
		return admittedCheckpoint{}, errors.New("cannot checkpoint an empty admitted log")
	}
	collection, err := admittedCollectionDigest(log.digests)
	if err != nil {
		return admittedCheckpoint{}, err
	}
	return admittedCheckpoint{
		Schema: admittedCheckpointSchema, Mode: admittedMode,
		RunID: cfg.RunID, ControllerConfigSHA256: configDigest,
		InstanceNonce: nonce, PredecessorNonce: predecessor,
		ReceiptCount: log.count, NextSequence: log.count + 1,
		LastReceiptDigest: log.head, ReceiptCollectionDigest: collection,
		LastBindingDigest:      log.last.BindingObjectDigest,
		LastIntentDigest:       log.last.IntentObjectDigest,
		LastResultSHA256:       log.last.ResultSHA256,
		AttemptInventoryDigest: inventoryDigest,
		MatrixCyclesExecuted:   0, HandoffReady: false,
		DispatchAuthorized: false, ExternalTopologyExecuted: false,
		ProviderAccess: false, CredentialAccess: false, Authority: false,
	}, nil
}

func compareAdmittedCheckpoint(
	value admittedCheckpoint, log *admittedReceiptLog,
	configDigest, inventoryDigest string,
) error {
	if value.ControllerConfigSHA256 != configDigest ||
		value.ReceiptCount != log.count || value.LastReceiptDigest != log.head ||
		value.AttemptInventoryDigest != inventoryDigest {
		return errors.New("admitted checkpoint/log/inventory mismatch")
	}
	collection, err := admittedCollectionDigest(log.digests)
	if err != nil || value.ReceiptCollectionDigest != collection {
		return fmt.Errorf("admitted receipt collection mismatch")
	}
	if log.last == nil ||
		value.LastBindingDigest != log.last.BindingObjectDigest ||
		value.LastIntentDigest != log.last.IntentObjectDigest ||
		value.LastResultSHA256 != log.last.ResultSHA256 {
		return errors.New("admitted checkpoint head projection mismatch")
	}
	return nil
}
