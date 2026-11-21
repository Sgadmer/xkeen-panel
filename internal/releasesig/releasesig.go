// Package releasesig verifies that the checksums of a panel release were
// approved by the holder of a release key.
//
// GitHub stores the release files, so whoever controls the repository can
// replace both a binary and its SHA256SUMS. The signature is made on the
// maintainer's computer with a key that never reaches GitHub; a panel installs
// an update only when the checksums carry it.
package releasesig

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// Asset is the name of the signature file in a release.
const Asset = "SHA256SUMS.sig"

// The first line of every signed message. A signature made for anything else
// with the same key cannot pass for a release.
const purpose = "xkeen-panel release checksums v1"

const maxSignatures = 8

var (
	ErrNoSignature  = errors.New("у выпуска нет подписи")
	ErrBadSignature = errors.New("подпись выпуска не подтверждена")
)

// Message is what a signature covers: the purpose, the tag and the exact
// bytes of SHA256SUMS. The tag keeps the checksums of one release from being
// republished under another version.
func Message(tag string, sums []byte) []byte {
	message := make([]byte, 0, len(purpose)+len(tag)+len(sums)+2)
	message = append(message, purpose...)
	message = append(message, '\n')
	message = append(message, tag...)
	message = append(message, '\n')
	return append(message, sums...)
}

// Sign returns one line for the signature file.
func Sign(key ed25519.PrivateKey, tag string, sums []byte) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(key, Message(tag, sums)))
}

// Verify accepts the checksums when any line of the signature file was made
// by any trusted key. Several lines let a release carry the signature of the
// spare key next to the main one.
func Verify(trusted []ed25519.PublicKey, tag string, sums, signatures []byte) error {
	if len(trusted) == 0 {
		return errors.New("в этой сборке нет ключей для проверки выпусков")
	}
	if strings.TrimSpace(tag) == "" || strings.ContainsAny(tag, "\r\n") {
		return ErrBadSignature
	}
	message := Message(tag, sums)
	scanner := bufio.NewScanner(bytes.NewReader(signatures))
	seen := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if seen++; seen > maxSignatures {
			break
		}
		signature, err := base64.StdEncoding.DecodeString(line)
		if err != nil || len(signature) != ed25519.SignatureSize {
			continue
		}
		for _, key := range trusted {
			if ed25519.Verify(key, message, signature) {
				return nil
			}
		}
	}
	if seen == 0 {
		return ErrNoSignature
	}
	return ErrBadSignature
}

// ParsePublicKey reads the text form of a public key: base64 of its 32 bytes.
func ParsePublicKey(text string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(text))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("открытый ключ выпуска записан неверно")
	}
	return ed25519.PublicKey(raw), nil
}

// ParsePrivateKey reads the text form of a private key: base64 of its 32-byte seed.
func ParsePrivateKey(text string) (ed25519.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(text))
	if err != nil || len(raw) != ed25519.SeedSize {
		return nil, fmt.Errorf("закрытый ключ выпуска записан неверно")
	}
	return ed25519.NewKeyFromSeed(raw), nil
}

// EncodePublicKey is the text form ParsePublicKey reads.
func EncodePublicKey(key ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(key)
}
