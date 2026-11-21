package auth

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"image/png"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// GenerateTOTP creates a new TOTP secret and its QR code.
func GenerateTOTP(username string) (secret string, qrBase64 string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "XKeen Panel",
		AccountName: username,
	})
	if err != nil {
		return "", "", fmt.Errorf("генерация TOTP: %w", err)
	}

	// Render the QR code
	img, err := key.Image(256, 256)
	if err != nil {
		return "", "", fmt.Errorf("генерация QR-изображения: %w", err)
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return "", "", fmt.Errorf("кодирование PNG: %w", err)
	}

	qrBase64 = "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())

	return key.Secret(), qrBase64, nil
}

// ValidateTOTP checks a TOTP code.
func ValidateTOTP(code, secret string) bool {
	_, ok := MatchTOTP(code, secret, time.Now())
	return ok
}

const totpPeriod = 30

// MatchTOTP reports which 30-second step the code belongs to. Like the
// authenticator apps it accepts the current step and one on either side, which
// covers a clock that is a little off. The step lets the caller refuse a code
// that has already been used.
func MatchTOTP(code, secret string, now time.Time) (int64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != 6 || secret == "" {
		return 0, false
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	current := now.Unix() / totpPeriod
	matched, found := int64(0), false
	for _, step := range []int64{current - 1, current, current + 1} {
		want, err := totp.GenerateCodeCustom(secret, time.Unix(step*totpPeriod, 0), totp.ValidateOpts{
			Period: totpPeriod, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
		})
		// Compare every candidate: the time taken does not depend on which matched.
		if err == nil && subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			matched, found = step, true
		}
	}
	return matched, found
}
