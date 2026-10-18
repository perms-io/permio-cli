// Package apikey validates perms.io API keys locally, before any request is made.
//
// Opaque keys are "perms_" followed by 32 random base62 characters and 6 base62
// characters encoding the CRC32 (IEEE) checksum of those 32, 44 characters in
// total. Legacy JWT keys are accepted too and are only checked for their
// three-part shape.
package apikey

import (
	"errors"
	"fmt"
	"hash/crc32"
	"regexp"
	"strings"
)

const (
	// Prefix starts every opaque API key.
	Prefix         = "perms_"
	randomLength   = 32
	checksumLength = 6
	// Length is the total length of an opaque API key.
	Length   = len(Prefix) + randomLength + checksumLength
	alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

// Kind says which form a key has.
type Kind string

const (
	// Opaque is a "perms_" key from the dashboard.
	Opaque Kind = "opaque"
	// JWT is a legacy JWT key.
	JWT Kind = "jwt"
)

// ErrMissing is returned by Validate for an empty key.
var ErrMissing = errors.New("no API key configured")

var jwtShape = regexp.MustCompile(`^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`)

// Validate checks that key looks like a perms.io API key and returns its kind.
// It catches typos and truncated keys; only the API can say whether a key
// exists and is still valid.
func Validate(key string) (Kind, error) {
	if key == "" {
		return "", ErrMissing
	}
	if strings.HasPrefix(key, Prefix) {
		if len(key) != Length {
			return "", fmt.Errorf("malformed API key: expected %d characters starting with %q, got %d", Length, Prefix, len(key))
		}
		rest := key[len(Prefix):]
		for _, r := range rest {
			if !strings.ContainsRune(alphabet, r) {
				return "", errors.New("malformed API key: characters after perms_ must be 0-9, A-Z or a-z")
			}
		}
		if checksum(rest[:randomLength]) != rest[randomLength:] {
			return "", errors.New("API key checksum mismatch: check that it was copied correctly")
		}
		return Opaque, nil
	}
	if jwtShape.MatchString(key) {
		return JWT, nil
	}
	return "", errors.New(`malformed API key: expected a "perms_" key from the dashboard, or a legacy JWT key`)
}

// WithChecksum returns the opaque key for a 32-character base62 body. It exists
// so tests can build well-formed keys; real keys come from the dashboard.
func WithChecksum(body string) (string, error) {
	if len(body) != randomLength {
		return "", fmt.Errorf("body must be %d characters", randomLength)
	}
	for _, r := range body {
		if !strings.ContainsRune(alphabet, r) {
			return "", errors.New("body must be base62")
		}
	}
	return Prefix + body + checksum(body), nil
}

// Redact shortens a key for display, keeping enough to recognise it.
func Redact(key string) string {
	if key == "" {
		return ""
	}
	if strings.HasPrefix(key, Prefix) && len(key) > len(Prefix)+4 {
		return key[:len(Prefix)+4] + "…" + key[len(key)-4:]
	}
	if len(key) > 8 {
		return key[:4] + "…" + key[len(key)-4:]
	}
	return "****"
}

func checksum(body string) string {
	value := crc32.ChecksumIEEE([]byte(body))
	out := make([]byte, checksumLength)
	for i := checksumLength - 1; i >= 0; i-- {
		out[i] = alphabet[value%62]
		value /= 62
	}
	return string(out)
}
