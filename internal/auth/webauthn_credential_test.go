package auth

import (
	"errors"
	"strings"
	"testing"
)

func TestNormalizeWebAuthnCredentialName_TrimsWhitespace(t *testing.T) {
	name, err := NormalizeWebAuthnCredentialName("  会社支給MacBook  ")
	if err != nil {
		t.Fatalf("NormalizeWebAuthnCredentialName: %v", err)
	}
	if name != "会社支給MacBook" {
		t.Fatalf("expected surrounding whitespace to be trimmed, got %q", name)
	}
}

func TestNormalizeWebAuthnCredentialName_EmptyIsValid(t *testing.T) {
	name, err := NormalizeWebAuthnCredentialName("")
	if err != nil {
		t.Fatalf("expected an empty name to be valid (unnamed), got %v", err)
	}
	if name != "" {
		t.Fatalf("expected an empty result, got %q", name)
	}
}

func TestNormalizeWebAuthnCredentialName_RejectsOverlyLongName(t *testing.T) {
	tooLong := strings.Repeat("a", maxWebAuthnCredentialNameLength+1)
	if _, err := NormalizeWebAuthnCredentialName(tooLong); !errors.Is(err, ErrInvalidWebAuthnCredentialName) {
		t.Fatalf("expected ErrInvalidWebAuthnCredentialName for a name over %d characters, got %v", maxWebAuthnCredentialNameLength, err)
	}
}

func TestNormalizeWebAuthnCredentialName_AllowsExactlyMaxLength(t *testing.T) {
	exact := strings.Repeat("a", maxWebAuthnCredentialNameLength)
	name, err := NormalizeWebAuthnCredentialName(exact)
	if err != nil {
		t.Fatalf("expected a name of exactly the max length to be valid, got %v", err)
	}
	if name != exact {
		t.Fatalf("expected the name to pass through unchanged, got %q", name)
	}
}
