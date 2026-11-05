package state

import "testing"

func TestPostgresLeaseKeysPreserveSignedBigEndianBitPattern(t *testing.T) {
	digest := [32]byte{
		0x7f, 0xff, 0xff, 0xff,
		0x80, 0x00, 0x00, 0x01,
	}
	keys := postgresLeaseKeys(digest)
	if keys[0] != 2147483647 {
		t.Fatalf("positive advisory key = %d, want 2147483647", keys[0])
	}
	if keys[1] != -2147483647 {
		t.Fatalf("negative advisory key = %d, want -2147483647", keys[1])
	}
}
