package releasesig

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return public, private
}

func TestVerifyAcceptsOnlyTheSignedRelease(t *testing.T) {
	public, private := testKey(t)
	stranger, strangerKey := testKey(t)
	sums := []byte("aa  xkeen-panel-aarch64\nbb  xkeen-panel-mipsel\n")
	signature := []byte(Sign(private, "v3.1.0", sums) + "\n")
	trusted := []ed25519.PublicKey{stranger, public}

	if err := Verify(trusted, "v3.1.0", sums, signature); err != nil {
		t.Fatalf("a valid signature was refused: %v", err)
	}
	// Comments, blank lines and a line of another key do not get in the way.
	mixed := []byte("# main key\n\n" + Sign(strangerKey, "v0.0.1", sums) + "\nnot base64\n" + string(signature))
	if err := Verify([]ed25519.PublicKey{public}, "v3.1.0", sums, mixed); err != nil {
		t.Fatalf("the right line among others was refused: %v", err)
	}

	changed := []byte(strings.Replace(string(sums), "aa", "ab", 1))
	for name, err := range map[string]error{
		"changed checksums": Verify(trusted, "v3.1.0", changed, signature),
		"another version":   Verify(trusted, "v3.1.1", sums, signature),
		"unknown key":       Verify([]ed25519.PublicKey{stranger}, "v3.1.0", sums, signature),
		"empty tag":         Verify(trusted, "", sums, signature),
		"tag with a break":  Verify(trusted, "v3.1.0\n", sums, signature),
	} {
		if !errors.Is(err, ErrBadSignature) {
			t.Errorf("%s: got %v", name, err)
		}
	}
	if err := Verify(trusted, "v3.1.0", sums, []byte("# nothing here\n\n")); !errors.Is(err, ErrNoSignature) {
		t.Errorf("an empty file is not a missing signature: %v", err)
	}
	if err := Verify(nil, "v3.1.0", sums, signature); err == nil {
		t.Error("a build without keys accepted a release")
	}
}

// The tag ends at the first line break of the message. A tag that carries one
// could borrow the first line of the checksums, so it is never accepted.
func TestTagCannotBorrowFromChecksums(t *testing.T) {
	public, private := testKey(t)
	signature := []byte(Sign(private, "v1.0.0", []byte("x\ny")))
	if err := Verify([]ed25519.PublicKey{public}, "v1.0.0\nx", []byte("y"), signature); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("a tag with a line break was accepted: %v", err)
	}
}

func TestKeysSurviveTheirTextForm(t *testing.T) {
	public, private := testKey(t)
	back, err := ParsePublicKey(" " + EncodePublicKey(public) + "\n")
	if err != nil || !back.Equal(public) {
		t.Fatalf("public key changed: %v", err)
	}
	for _, bad := range []string{"", "AAAA", EncodePublicKey(public) + "AA", "не ключ"} {
		if _, err := ParsePublicKey(bad); err == nil {
			t.Errorf("accepted public key %q", bad)
		}
		if _, err := ParsePrivateKey(bad); err == nil {
			t.Errorf("accepted private key %q", bad)
		}
	}
	if len(private.Seed()) != ed25519.SeedSize {
		t.Fatal("unexpected seed size")
	}
}

// The installer checks the same signatures in Python. This fixed example is
// also in installer/tests: if the message or the encoding ever changes on one
// side only, one of the two tests fails.
func TestSignatureMatchesTheSharedExample(t *testing.T) {
	const (
		public    = "6kpsY+KcUgq+9VB7Ey7F+ZVHdq6+vnuSQh7qaRRG0iw="
		signature = "ZbGXM4xl1j5l9J2KFWJDQLWM6XkOIh9Y1ihbLDXw6YGjeh236gu8mj5rYsP+pmkz5ablourYz3iMdWguVcdHDQ=="
	)
	sums := []byte("aa  xkeen-panel-aarch64\nbb  xkeen-panel-mipsel\n")
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	if got := EncodePublicKey(key.Public().(ed25519.PublicKey)); got != public {
		t.Fatalf("public key of the example changed: %s", got)
	}
	if got := Sign(key, "v1.2.3", sums); got != signature {
		t.Fatalf("signature of the example changed: %s", got)
	}
}

// The installer must read the keys from the same file as the panel: a fork
// replaces that one file and nothing else.
func TestInstallerReadsTheSameKeyFile(t *testing.T) {
	script, err := os.ReadFile(filepath.Join("..", "..", "installer", "release_signature.py"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(script), "'internal', 'releasesig', 'release-keys.txt'") {
		t.Fatal("installer/release_signature.py does not read internal/releasesig/release-keys.txt")
	}
	if strings.Contains(string(script), "=',") {
		t.Fatal("the installer carries its own copy of a key")
	}
}

func TestKeyFileFormat(t *testing.T) {
	public, _ := testKey(t)
	text := "# comment\n\n" + EncodePublicKey(public) + "  main key\n"
	keys, err := parseKeys(text)
	if err != nil || len(keys) != 1 || !keys[0].Equal(public) {
		t.Fatalf("a valid file was not read: %v", err)
	}
	for name, bad := range map[string]string{"empty": "# only a comment\n", "broken key": "not-a-key\n"} {
		if _, err := parseKeys(bad); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Every embedded key must be readable, or a release build would refuse all updates.
func TestTrustedKeysAreValid(t *testing.T) {
	keys, err := Trusted()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) < 2 {
		t.Fatalf("a main and a spare key are expected, got %d", len(keys))
	}
	if keys[0].Equal(keys[1]) {
		t.Fatal("the spare key repeats the main one")
	}
}
