package xkeen

import "testing"

func TestAnalyticsCollectorLabelsAreExactAndDoNotCaptureVendorWebsites(t *testing.T) {
	for _, host := range AnalyticsHosts() {
		if ServiceForHost(host) != "analytics" {
			t.Fatal("collector was not labelled", host)
		}
		if ServiceForHost("other."+host) == "analytics" {
			t.Fatal("exact collector matched a subdomain", host)
		}
	}
	for _, host := range []string{"siftscience.com", "sentry.io", "datadoghq.com", "fcmtoken.googleapis.com"} {
		if ServiceForHost(host) == "analytics" {
			t.Fatal("unrelated website or push service was captured", host)
		}
	}
	names := ServiceNames()
	for i, service := range names {
		if service.ID == "analytics" {
			if i == 0 || names[i-1].ID != "openai" {
				t.Fatal("analytics default position is not after ChatGPT")
			}
			return
		}
	}
	t.Fatal("analytics card is missing")
}
