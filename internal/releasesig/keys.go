package releasesig

import (
	"bufio"
	"crypto/ed25519"
	_ "embed"
	"errors"
	"strings"
)

// The public halves of the release keys. The private halves are kept by the
// maintainer outside GitHub; see docs/release-signing.md.
//
// The file is the single place a fork replaces to release under its own keys:
// the installer reads the same file. A second key is a spare: it lets a
// release be signed, and the list be replaced, if the main key is lost or
// leaks. Removing a key stops newer builds from trusting it.
//
//go:embed release-keys.txt
var keysFile string

// Trusted returns the keys this build accepts release signatures from.
func Trusted() ([]ed25519.PublicKey, error) {
	return parseKeys(keysFile)
}

func parseKeys(text string) ([]ed25519.PublicKey, error) {
	var keys []ed25519.PublicKey
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		key, err := ParsePublicKey(fields[0])
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		return nil, errors.New("в файле ключей выпусков нет ни одного ключа")
	}
	return keys, nil
}
