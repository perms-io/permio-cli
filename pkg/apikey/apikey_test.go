package apikey

import (
	"strings"
	"testing"
)

func TestValidate(t *testing.T) {
	good, err := WithChecksum("abcdefghijklmnopqrstuvwxyz012345")
	if err != nil {
		t.Fatal(err)
	}
	if len(good) != Length {
		t.Fatalf("length %d, want %d", len(good), Length)
	}
	// A typo in the body must break the checksum.
	typo := good[:10] + "Z" + good[11:]

	cases := []struct {
		name    string
		key     string
		kind    Kind
		wantErr string
	}{
		{"opaque", good, Opaque, ""},
		{"jwt", "eyJhbGciOi.eyJzdWIiOi.c2lnbmF0dXJl", JWT, ""},
		{"empty", "", "", "no API key"},
		{"short", "perms_abc", "", "expected 44 characters"},
		{"bad alphabet", Prefix + strings.Repeat("-", 38), "", "must be 0-9"},
		{"checksum", typo, "", "checksum mismatch"},
		{"garbage", "not-a-key", "", "malformed API key"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kind, err := Validate(tc.key)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || kind != tc.kind {
				t.Fatalf("got %q, %v; want %q", kind, err, tc.kind)
			}
		})
	}
}

// The checksum must match the JS SDK and the server (go-common/middleware/apikey).
// These vectors were computed with permio-js's implementation.
func TestChecksumVectors(t *testing.T) {
	for body, want := range map[string]string{
		"00000000000000000000000000000000": "2wjyrI",
		"Zx9QwErTyUiOpAsDfGhJkLzXcVbNm123": "4SnqYR",
	} {
		key, err := WithChecksum(body)
		if err != nil {
			t.Fatal(err)
		}
		if got := key[len(Prefix)+32:]; got != want {
			t.Errorf("checksum(%s) = %s, want %s", body, got, want)
		}
	}
}

func TestRedact(t *testing.T) {
	key, _ := WithChecksum("abcdefghijklmnopqrstuvwxyz012345")
	r := Redact(key)
	if strings.Contains(r, "mnop") || !strings.HasPrefix(r, "perms_abcd") {
		t.Fatalf("redact = %q", r)
	}
}
