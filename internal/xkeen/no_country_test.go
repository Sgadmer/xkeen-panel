package xkeen

import (
	"testing"

	"xkeen-panel/internal/models"
)

// «Без страны» in the excluded locations is ZZ; it takes out exactly the
// servers whose subscription gives no location.
func TestServersWithoutLocationCanBeExcluded(t *testing.T) {
	plain := models.Server{Name: "Обход V"}
	german := models.Server{Name: "Германия", Country: "DE"}
	if CountryExcluded(plain, []string{"RU"}) || CountryExcluded(german, []string{NoCountryCode}) {
		t.Fatal("ZZ must touch only servers without a location, and RU none of these")
	}
	if !CountryExcluded(plain, []string{"ru", NoCountryCode}) || !CountryExcluded(german, []string{"de"}) {
		t.Fatal("an excluded location must take its servers out")
	}
}

// «Режимы провайдера» takes out every complete profile and nothing else.
func TestProviderModesCanBeExcludedTogether(t *testing.T) {
	mode := models.Server{Name: "Самый быстрый", Country: "DE", Protocol: "xray-profile", RawProfile: []byte(`{"outbounds":[]}`)}
	server := models.Server{Name: "Германия", Country: "DE"}
	if !CountryExcluded(mode, []string{ProviderModesCode}) || CountryExcluded(server, []string{ProviderModesCode}) {
		t.Fatal("XP must take out the provider's modes and only them")
	}
	if CountryExcluded(mode, []string{"RU"}) || !CountryExcluded(mode, []string{"DE"}) {
		t.Fatal("a mode is still judged by its own location too")
	}
}
