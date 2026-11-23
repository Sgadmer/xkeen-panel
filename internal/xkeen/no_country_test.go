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
