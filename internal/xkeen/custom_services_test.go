package xkeen

import (
	"os"
	"slices"
	"strings"
	"testing"
)

const customID = "custom-0a1b2c3d"

func TestNormalizeCustomService(t *testing.T) {
	service, err := NormalizeCustomService(customID, "  Мой   банк ", []string{
		"bank.example.org", "", "# заметка", "https://pay.example.org/login?x=1", "full:API.Example.net.",
		"bank.example.org", "203.0.113.7", "198.51.100.0/24", "2001:db8::/32",
	})
	if err != nil {
		t.Fatal(err)
	}
	if service.Name != "Мой банк" || !slices.Equal(service.Domains, []string{"domain:bank.example.org", "domain:pay.example.org", "full:api.example.net"}) ||
		!slices.Equal(service.Networks, []string{"203.0.113.7/32", "198.51.100.0/24", "2001:db8::/32"}) {
		t.Fatalf("unexpected form: %+v", service)
	}
	// What the owner edits is what was entered, without the internal prefixes of domains.
	if got := service.Addresses(); !slices.Equal(got, []string{"bank.example.org", "pay.example.org", "full:api.example.net", "203.0.113.7/32", "198.51.100.0/24", "2001:db8::/32"}) {
		t.Fatalf("addresses for editing: %v", got)
	}

	refused := map[string][]string{
		"no address":        {"", "# only a note"},
		"a pattern":         {"*.example.org"},
		"not an address":    {"hello world"},
		"a bare word":       {"localhost"},
		"the whole network": {"0.0.0.0/0"},
		"half the internet": {"128.0.0.0/1"},
	}
	for name, addresses := range refused {
		if _, err := NormalizeCustomService(customID, "Сервис", addresses); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	for name, args := range map[string][2]string{
		"empty name":      {customID, "   "},
		"long name":       {customID, strings.Repeat("я", maxCustomNameRunes+1)},
		"control symbol":  {customID, "bad\x07name"},
		"foreign id":      {"claude", "Сервис"},
		"malformed id":    {"custom-XYZ", "Сервис"},
		"id of a builtin": {"custom-", "Сервис"},
	} {
		if _, err := NormalizeCustomService(args[0], args[1], []string{"example.org"}); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	many := make([]string, 0, maxCustomAddresses+1)
	for i := 0; i <= maxCustomAddresses; i++ {
		many = append(many, "h"+strings.Repeat("a", i%20+1)+string(rune('a'+i%26))+string(rune('a'+i/26%26))+".example.org")
	}
	if _, err := NormalizeCustomService(customID, "Сервис", many); err == nil {
		t.Error("more addresses than the limit were accepted")
	}
}

func TestCustomServicesJoinTheCatalogue(t *testing.T) {
	t.Cleanup(func() { SetCustomServices(nil) })
	service, err := NormalizeCustomService(customID, "Мой банк", []string{"bank.example.org", "full:pay.example.net", "203.0.113.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	SetCustomServices([]CustomService{service})

	names := ServiceNames()
	if last := names[len(names)-1]; last.ID != customID || last.Name != "Мой банк" || names[0].ID != "claude" {
		t.Fatalf("the owner's card must follow the built-in ones: first %+v, last %+v", names[0], last)
	}
	for host, want := range map[string]string{
		"bank.example.org": customID, "online.bank.example.org": customID, "pay.example.net": customID,
		"x.pay.example.net": "", "example.org": "", "claude.ai": "claude", "notbank.example.org": "",
	} {
		if got := ServiceForHost(host); got != want {
			t.Errorf("ServiceForHost(%s) = %q, want %q", host, got, want)
		}
	}
	if !IsCustomService(customID) || IsCustomService("custom-ffffffff") || !CustomServiceID("custom-ffffffff") || CustomServiceID("claude") {
		t.Fatal("custom identifiers are told apart wrongly")
	}
	if !slices.Equal(ServiceSuffixes(customID), []string{"bank.example.org"}) || !slices.Equal(ServiceHosts(customID), []string{"pay.example.net"}) ||
		!slices.Equal(ServiceNetworks(customID), []string{"203.0.113.0/24"}) || len(ServiceHosts("claude")) != 0 {
		t.Fatal("the addresses of the owner's card are reported wrongly")
	}
	// The card exists for the Mihomo card controller only.
	view, err := ReadServiceRoutes(Runtime{Core: CoreMihomo, XrayConfDir: t.TempDir() + "/config"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if last := view.Services[len(view.Services)-1]; last.ID != customID || !last.Custom || !slices.Equal(last.Networks, []string{"203.0.113.0/24"}) {
		t.Fatalf("the Mihomo view lacks the owner's card: %+v", last)
	}
	view, err = ReadServiceRoutes(Runtime{Core: CoreXray, XrayConfDir: t.TempDir() + "/config"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, service := range view.Services {
		if service.Custom {
			t.Fatal("the owner's card appeared for the Xray core")
		}
	}
	// The registry hands out copies.
	CustomServices()[0].Domains[0] = "domain:changed.example"
	if ServiceForHost("bank.example.org") != customID {
		t.Fatal("a caller changed the registry through a returned list")
	}
}

func TestCustomServicesFile(t *testing.T) {
	dir := t.TempDir()
	if list, err := LoadCustomServices(dir); err != nil || list != nil {
		t.Fatalf("no file must mean no cards: %v %v", list, err)
	}
	service, _ := NormalizeCustomService(customID, "Мой банк", []string{"bank.example.org", "203.0.113.0/24"})
	if err := SaveCustomServices(dir, []CustomService{service}); err != nil {
		t.Fatal(err)
	}
	list, err := LoadCustomServices(dir)
	if err != nil || len(list) != 1 || list[0].Name != "Мой банк" || !slices.Equal(list[0].Networks, service.Networks) {
		t.Fatalf("saved cards were not read back: %+v %v", list, err)
	}
	for name, body := range map[string]string{
		"not json":         `{`,
		"unnormalised":     `{"services":[{"id":"custom-0a1b2c3d","name":"x","domains":["Example.ORG"]}]}`,
		"foreign id":       `{"services":[{"id":"claude","name":"x","domains":["domain:example.org"]}]}`,
		"twice the same":   `{"services":[{"id":"custom-0a1b2c3d","name":"x","domains":["domain:a.example"]},{"id":"custom-0a1b2c3d","name":"y","domains":["domain:b.example"]}]}`,
		"without an entry": `{"services":[{"id":"custom-0a1b2c3d","name":"x","domains":[]}]}`,
	} {
		if err := os.WriteFile(CustomServicesPath(dir), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadCustomServices(dir); err == nil {
			t.Errorf("%s: a damaged file was accepted", name)
		}
	}
}
