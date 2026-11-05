package main

import (
	"strings"
	"testing"
)

func TestDartShapedQuickToUserspace(t *testing.T) {
	const privateKey = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
	const publicKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	const privateHex = "c809f3e5317e9575c9b5ed78b638b7ce530dabe85ddab614220241801ddf0669"
	const publicHex = "0000000000000000000000000000000000000000000000000000000000000000"
	quick := `[Interface]
PrivateKey = ` + privateKey + `
Address = 10.8.1.3/32
MTU = 1280
DNS = 10.8.1.1
Jc = 2
S4 = 0
H1 = 11

[Peer]
PublicKey = ` + publicKey + `
Endpoint = 127.0.0.1:1
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`
	got, err := adaptQuickOrUserspace(quick)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got, "private_key="+privateHex+"\n") {
		t.Fatalf("private_key must lead, got %q", got)
	}
	if !strings.Contains(got, "replace_peers=true\n") {
		t.Fatalf("turn-on must replace peers, got %q", got)
	}
	if !strings.Contains(got, "public_key="+publicHex+"\n") {
		t.Fatalf("missing public_key, got %q", got)
	}
	if strings.Contains(got, "s4=") {
		t.Fatalf("zero S4 must be omitted, got %q", got)
	}
	if strings.Contains(got, "10.8.1.3") {
		t.Fatalf("Address must not enter UAPI, got %q", got)
	}
	update, err := adaptPeerUpdate(quick)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(update, "private_key=") || strings.Contains(update, "replace_peers=") {
		t.Fatalf("peer update must be peer-only, got %q", update)
	}
}

func TestUserspacePassthrough(t *testing.T) {
	uapi := "private_key=00\npublic_key=00\n"
	got, err := adaptQuickOrUserspace(uapi)
	if err != nil {
		t.Fatal(err)
	}
	if got != uapi {
		t.Fatalf("UAPI must pass through, got %q", got)
	}
}

func TestUnknownAttributeFailsClosed(t *testing.T) {
	_, err := adaptQuickOrUserspace(`[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Nope = 1
[Peer]
PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
`)
	if err == nil || !strings.Contains(err.Error(), "unknown [Interface] attribute") {
		t.Fatalf("expected unknown attribute error, got %v", err)
	}
}
