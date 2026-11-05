package peer

import (
	"encoding/base64"
	"net/netip"
	"testing"
)

func query(name string, qtype byte) []byte {
	q := []byte{0xAB, 0xCD, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range splitLabels(name) {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	return append(q, 0, 0, qtype, 0, 1)
}

func splitLabels(name string) []string {
	var labels []string
	current := ""
	for _, r := range name {
		if r == '.' {
			labels = append(labels, current)
			current = ""
		} else {
			current += string(r)
		}
	}
	return append(labels, current)
}

func TestAnswerIsOnlyForTheNameAsked(t *testing.T) {
	address := netip.MustParseAddr("192.0.2.7")
	reply := Answer(query("hub.example.test", 1), "hub.example.test", address)
	if reply == nil || reply[0] != 0xAB || reply[1] != 0xCD || reply[2]&0x80 == 0 || reply[3]&0x0F != 0 {
		t.Fatalf("reply %x", reply)
	}
	if reply[7] != 1 || string(reply[len(reply)-4:]) != string([]byte{192, 0, 2, 7}) {
		t.Fatalf("no address record: %x", reply)
	}
	other := Answer(query("other.example.test", 1), "hub.example.test", address)
	if other == nil || other[3]&0x0F != 3 || other[7] != 0 {
		t.Fatalf("another name must be NXDOMAIN without records: %x", other)
	}
	if Answer([]byte{1, 2, 3}, "hub.example.test", address) != nil {
		t.Fatal("a malformed query was answered")
	}
	response := query("hub.example.test", 1)
	response[2] |= 0x80
	if Answer(response, "hub.example.test", address) != nil {
		t.Fatal("a response was answered")
	}
}

func TestNewKeypairIsAClampedX25519Key(t *testing.T) {
	keys, err := NewKeypair()
	if err != nil {
		t.Fatal(err)
	}
	private, _ := base64.StdEncoding.DecodeString(keys.Private)
	public, _ := base64.StdEncoding.DecodeString(keys.Public)
	if len(private) != 32 || len(public) != 32 || private[0]&7 != 0 || private[31]&128 != 0 || private[31]&64 == 0 {
		t.Fatal("not a clamped 32-byte key pair")
	}
	again, _ := NewKeypair()
	if again.Private == keys.Private {
		t.Fatal("two draws gave the same key")
	}
}
