package xkeen

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"

	"xkeen-panel/internal/models"
)

// Happ lets a provider add a short note under a server's name: in a link as
// "#Name?serverDescription=<base64>", in Xray JSON as
// "meta": {"serverDescription": "text"}. Happ shows up to 30 characters.
const serverDescriptionKey = "?serverDescription="
const maxServerDescription = 60

// SplitServerDescription separates the note from a link name. The note may be
// base64 or plain text; a name without one comes back unchanged.
func SplitServerDescription(name string) (string, string) {
	index := strings.Index(name, serverDescriptionKey)
	if index < 0 {
		return name, ""
	}
	value := name[index+len(serverDescriptionKey):]
	if end := strings.IndexByte(value, '&'); end >= 0 {
		value = value[:end]
	}
	clean := strings.TrimSpace(name[:index])
	if clean == "" {
		// A note alone is no name: keep the original text.
		return name, ""
	}
	return clean, decodeServerDescription(value)
}

func decodeServerDescription(value string) string {
	if unescaped, err := url.QueryUnescape(value); err == nil {
		value = unescaped
	}
	value = strings.TrimSpace(value)
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding} {
		// Plain words can be valid base64 too; only readable text counts.
		if decoded, err := encoding.DecodeString(value); err == nil && len(decoded) > 0 && readable(decoded) {
			value = string(decoded)
			break
		}
	}
	return cleanServerDescription(value)
}

func readable(text []byte) bool {
	if !utf8.Valid(text) {
		return false
	}
	for _, r := range string(text) {
		if !unicode.IsPrint(r) && r != ' ' {
			return false
		}
	}
	return true
}

func cleanServerDescription(value string) string {
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, value)
	value = strings.Join(strings.Fields(value), " ")
	if utf8.RuneCountInString(value) > maxServerDescription {
		value = string([]rune(value)[:maxServerDescription]) + "…"
	}
	return value
}

// objectDescription reads Happ's JSON form of the note.
func objectDescription(object map[string]json.RawMessage) string {
	var meta struct {
		ServerDescription string `json:"serverDescription"`
	}
	if raw, ok := object["meta"]; !ok || json.Unmarshal(raw, &meta) != nil {
		return ""
	}
	return cleanServerDescription(meta.ServerDescription)
}

func describe(servers []models.Server, description string) {
	if description == "" {
		return
	}
	for i := range servers {
		if servers[i].Description == "" {
			servers[i].Description = description
		}
	}
}
