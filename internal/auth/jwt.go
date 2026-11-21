package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	tokenExpiry = 24 * time.Hour
	// A device the owner chose to remember. The session is renewed while the
	// panel is in use and ends after this long without a visit.
	rememberedExpiry = 30 * 24 * time.Hour
)

// Session is what a valid token says about its holder.
type Session struct {
	Username string
	IssuedAt time.Time
	Remember bool
}

// GenerateToken issues a one-day JWT.
func GenerateToken(username, secret string) (string, error) {
	return IssueToken(username, secret, false)
}

// IssueToken issues a JWT; a remembered device gets a long-lived one.
func IssueToken(username, secret string, remember bool) (string, error) {
	now := time.Now()
	life := tokenExpiry
	if remember {
		life = rememberedExpiry
	}
	claims := jwt.MapClaims{
		"sub": username,
		"iat": now.Unix(),
		"exp": now.Add(life).Unix(),
	}
	if remember {
		claims["rem"] = true
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

// ValidateToken verifies a JWT and returns its username.
func ValidateToken(tokenString, secret string) (string, error) {
	session, err := ReadToken(tokenString, secret)
	return session.Username, err
}

// ReadToken verifies a JWT and returns what it carries.
func ReadToken(tokenString, secret string) (Session, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("неожиданный метод подписи: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	}, jwt.WithValidMethods([]string{"HS256"}), jwt.WithExpirationRequired())
	if err != nil {
		return Session{}, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return Session{}, fmt.Errorf("невалидный токен")
	}

	sub, ok := claims["sub"].(string)
	if !ok {
		return Session{}, fmt.Errorf("отсутствует поле sub")
	}
	session := Session{Username: sub}
	if issued, ok := claims["iat"].(float64); ok {
		session.IssuedAt = time.Unix(int64(issued), 0)
	}
	session.Remember, _ = claims["rem"].(bool)
	return session, nil
}
