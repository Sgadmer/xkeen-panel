package releasesig

import "crypto/ed25519"

// The public halves of the release keys. The private halves are kept by the
// maintainer outside GitHub; see docs/release-signing.md.
//
// The second key is a spare: it lets a release be signed, and this list be
// replaced, if the main key is lost or leaks. Removing a key from here stops
// newer builds from trusting it.
var trustedKeys = []string{
	"tm5lBEJxVT1nzx9v9974lIEKgfUmT3ORlKrphTt6flo=", // main
	"gL94OYrlbFXzy6ZaLjQaAGhF8d5TefHjX+JtpGnHDNY=", // spare
}

// Trusted returns the keys this build accepts release signatures from.
func Trusted() ([]ed25519.PublicKey, error) {
	keys := make([]ed25519.PublicKey, 0, len(trustedKeys))
	for _, text := range trustedKeys {
		key, err := ParsePublicKey(text)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, nil
}
