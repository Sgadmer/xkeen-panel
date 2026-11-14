package xkeen

import (
	"slices"
	"testing"

	"xkeen-panel/internal/models"
)

func TestExplicitProviderPath(t *testing.T) {
	for _, tt := range []struct {
		name string
		want []string
	}{
		{"🇷🇺 Россия → 🇨🇳 Китай → 🇫🇷 Франция", []string{"RU", "CN", "FR"}},
		{"Russia 🇷🇺 -> CN => FR", []string{"RU", "CN", "FR"}},
		{"🇷🇺 → 🇸🇴", []string{"RU", "SO"}},
		{"🇷🇺️ → 🇸🇴", []string{"RU", "SO"}},
		{"🇫🇷 Франция", nil},
		{"🇷🇺 🇫🇷", nil},
		{"🇷🇺 🇨🇳 → 🇫🇷", nil},
		{"🇷🇺 → 🇩🇪 Франция", nil},
		{"RU → 🇪🇺", nil},
		{"🇫🇷 → для стриминга", nil},
		{"🇫🇷 → → DE", nil},
		{"🇷🇺 → 192.0.2.1 → 🇳🇱", nil},
	} {
		if got := providerChainFromName(tt.name); !slices.Equal(got, tt.want) {
			t.Errorf("%q: got %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestDeclaredPathHonoursManualCountryAndSkipsDynamicProfiles(t *testing.T) {
	node := models.Server{Name: "RU → FR", Country: "RU"}
	if got := ServerCountry(node); got != "FR" {
		t.Fatalf("legacy first-flag country exposed instead of declared destination: %q", got)
	}
	node.CountryOverride = "FR"
	if got := ServerCountryPath(node); !slices.Equal(got, []string{"RU", "FR"}) {
		t.Fatalf("expected declared route, got %v", got)
	}
	node.CountryOverride = "CZ"
	if path := ServerCountryPath(node); path != nil || ServerCountry(node) != "CZ" {
		t.Fatalf("unexpected path %v for manually corrected destination", path)
	}
	node.CountryOverride = ""
	node.Protocol = "xray-profile"
	if got := ServerCountryPath(node); got != nil {
		t.Errorf("a dynamic profile has no single guaranteed path: %v", got)
	}
}

func TestProviderDestinationWithUnknownRelay(t *testing.T) {
	node := models.Server{Name: "🇷🇺 Первый узел → 🇫🇷 Франция", Country: "RU"}
	if dest := ServerCountry(node); dest != "FR" || detectCountry(node.Name) != "FR" || ServerCountryPath(node) != nil {
		t.Fatalf("expected only the declared French destination, got %q", dest)
	}
	node.Name = "🇷🇺 → ?"
	if dest := ServerCountry(node); dest != "" {
		t.Errorf("unknown destination inferred from an earlier country: %q", dest)
	}
}
