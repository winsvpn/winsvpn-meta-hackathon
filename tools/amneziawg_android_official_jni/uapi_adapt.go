package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

func looksLikeAwgQuick(settings string) bool {
	for _, line := range strings.Split(settings, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		lower := strings.ToLower(trimmed)
		if lower == "[interface]" || lower == "[peer]" {
			return true
		}
	}
	return false
}

func adaptQuickOrUserspace(settings string) (string, error) {
	if !looksLikeAwgQuick(settings) {
		return settings, nil
	}
	return quickToUserspace(settings, false)
}

func adaptPeerUpdate(settings string) (string, error) {
	if !looksLikeAwgQuick(settings) {
		return settings, nil
	}
	return quickToUserspace(settings, true)
}

func quickToUserspace(settings string, peersOnly bool) (string, error) {
	type section struct {
		name   string
		attrs  [][2]string
	}
	var sections []section
	var current *section
	for _, raw := range strings.Split(settings, "\n") {
		line := strings.TrimSpace(raw)
		if hash := strings.Index(line, "#"); hash >= 0 {
			line = strings.TrimSpace(line[:hash])
		}
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			if !strings.HasSuffix(line, "]") {
				return "", fmt.Errorf("malformed section header %q", line)
			}
			name := strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			if name != "interface" && name != "peer" {
				return "", fmt.Errorf("unsupported section %q", line)
			}
			sections = append(sections, section{name: name})
			current = &sections[len(sections)-1]
			continue
		}
		if current == nil {
			return "", fmt.Errorf("attribute outside a section: %q", line)
		}
		sep := strings.Index(line, "=")
		if sep <= 0 {
			return "", fmt.Errorf("malformed attribute %q", line)
		}
		key := strings.ToLower(strings.TrimSpace(line[:sep]))
		value := strings.TrimSpace(line[sep+1:])
		current.attrs = append(current.attrs, [2]string{key, value})
	}
	if len(sections) == 0 {
		return "", fmt.Errorf("empty AmneziaWG configuration")
	}

	var out strings.Builder
	sawInterface := false
	sawPeer := false
	for _, sec := range sections {
		switch sec.name {
		case "interface":
			if peersOnly {
				continue
			}
			if sawInterface {
				return "", fmt.Errorf("multiple [Interface] sections")
			}
			sawInterface = true
			if err := writeInterfaceUserspace(&out, sec.attrs); err != nil {
				return "", err
			}
		case "peer":
			if !peersOnly && !sawInterface {
				return "", fmt.Errorf("[Peer] before [Interface]")
			}
			if !peersOnly && !sawPeer {
				out.WriteString("replace_peers=true\n")
			}
			sawPeer = true
			if err := writePeerUserspace(&out, sec.attrs); err != nil {
				return "", err
			}
		}
	}
	if !peersOnly && !sawInterface {
		return "", fmt.Errorf("missing [Interface] section")
	}
	if !sawPeer {
		return "", fmt.Errorf("missing [Peer] section")
	}
	return out.String(), nil
}

var skippedInterfaceKeys = map[string]struct{}{
	"address":              {},
	"dns":                  {},
	"mtu":                  {},
	"table":                {},
	"excludedapplications": {},
	"includedapplications": {},
}

var boolInterfaceKeys = map[string]string{
	"randomtrailers": "random_trailers",
	"disablecookies": "disable_cookies",
}

var copiedInterfaceKeys = map[string]string{
	"listenport":             "listen_port",
	"jc":                     "jc",
	"jmin":                   "jmin",
	"jmax":                   "jmax",
	"s1":                     "s1",
	"s2":                     "s2",
	"s3":                     "s3",
	"s4":                     "s4",
	"h1":                     "h1",
	"h2":                     "h2",
	"h3":                     "h3",
	"h4":                     "h4",
	"i1":                     "i1",
	"i2":                     "i2",
	"i3":                     "i3",
	"i4":                     "i4",
	"i5":                     "i5",
	"contentpaddingaddition": "content_padding_addition",
	"rekeyaftertime":         "rekey_after_time",
	"rekeytimeout":           "rekey_timeout",
	"rejectaftertime":        "reject_after_time",
	"keepalivetimeout":       "keepalive_timeout",
	"maxhandshakeattempts":   "max_handshake_attempts",
}

func writeInterfaceUserspace(out *strings.Builder, attrs [][2]string) error {
	var privateKey string
	for _, attr := range attrs {
		key, value := attr[0], attr[1]
		if _, skip := skippedInterfaceKeys[key]; skip {
			continue
		}
		switch key {
		case "privatekey":
			hexKey, err := wgKeyToHex(value)
			if err != nil {
				return fmt.Errorf("PrivateKey: %w", err)
			}
			privateKey = hexKey
		case "headerprotectionkey":
			if value == "" {
				continue
			}
			hexKey, err := wgKeyToHex(value)
			if err != nil {
				return fmt.Errorf("HeaderProtectionKey: %w", err)
			}
			out.WriteString("header_protection_key=" + hexKey + "\n")
		default:
			if uapi, ok := boolInterfaceKeys[key]; ok {
				if value == "" {
					continue
				}
				out.WriteString(uapi + "=" + toUapiBool(value) + "\n")
				continue
			}
			if uapi, ok := copiedInterfaceKeys[key]; ok {
				if omitZeroInteger(key, value) {
					continue
				}
				if value == "" {
					continue
				}
				out.WriteString(uapi + "=" + value + "\n")
				continue
			}
			return fmt.Errorf("unknown [Interface] attribute %q", key)
		}
	}
	if privateKey == "" {
		return fmt.Errorf("missing PrivateKey")
	}
	// private_key must lead the userspace document, matching official Config.toAwgUserspaceString.
	prefixed := "private_key=" + privateKey + "\n" + out.String()
	out.Reset()
	out.WriteString(prefixed)
	return nil
}

func writePeerUserspace(out *strings.Builder, attrs [][2]string) error {
	var publicKey string
	var rest strings.Builder
	for _, attr := range attrs {
		key, value := attr[0], attr[1]
		switch key {
		case "publickey":
			hexKey, err := wgKeyToHex(value)
			if err != nil {
				return fmt.Errorf("PublicKey: %w", err)
			}
			publicKey = hexKey
		case "presharedkey":
			if value == "" {
				continue
			}
			hexKey, err := wgKeyToHex(value)
			if err != nil {
				return fmt.Errorf("PresharedKey: %w", err)
			}
			rest.WriteString("preshared_key=" + hexKey + "\n")
		case "endpoint":
			if value == "" {
				continue
			}
			rest.WriteString("endpoint=" + value + "\n")
		case "persistentkeepalive":
			trimmed := strings.TrimSpace(value)
			if trimmed == "" || strings.EqualFold(trimmed, "off") {
				continue
			}
			rest.WriteString("persistent_keepalive_interval=" + trimmed + "\n")
		case "allowedips":
			for _, cidr := range splitList(value) {
				rest.WriteString("allowed_ip=" + cidr + "\n")
			}
		default:
			return fmt.Errorf("unknown [Peer] attribute %q", key)
		}
	}
	if publicKey == "" {
		return fmt.Errorf("missing PublicKey")
	}
	out.WriteString("public_key=" + publicKey + "\n")
	out.WriteString(rest.String())
	return nil
}

func omitZeroInteger(key, value string) bool {
	switch key {
	case "listenport", "jc", "jmin", "jmax", "s1", "s2", "s3", "s4":
		n, err := strconv.Atoi(strings.TrimSpace(value))
		return err == nil && n == 0
	default:
		return false
	}
}

func toUapiBool(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "on", "1", "true", "t", "yes":
		return "1"
	default:
		return "0"
	}
}

func splitList(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func wgKeyToHex(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return "", err
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("key must be 32 bytes, got %d", len(raw))
	}
	return hex.EncodeToString(raw), nil
}
