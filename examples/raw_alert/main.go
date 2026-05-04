package main

import (
	"fmt"
	"time"

	"github.com/reflective-technology/cybereyes-cef/v3/alert"
)

func main() {
	rawAlert := alert.NewRawAlert(alert.RawAlertParam{
		Meta: alert.AlertMetaField{
			ID:           "a1b2c3d4-e5f6-7890-abcd-1234567890ab",
			RuleID:       "RULE-12345",
			Name:         "Suspicious Network Activity Detected",
			AlertSubject: "Potential Data Exfiltration Attempt",
			Description:  "Multiple large outbound data transfers detected from internal IP to unknown external destination.",
			Severity:     alert.AlertSeverityLow,
		},
		GeneralFields: map[string]string{
			"src":           "192.168.1.1",
			"dest":          "192.168.1.2",
			"src_port":      "80",
			"dest_port":     "8080",
			"http_method":   "GET",
			"http_referrer": "http://example.com",
			"url_domain":    "example.com",
			"user":          "testuser",
		},
	})

	cefString, err := rawAlert.ToSyslogRFC3164WithCef(alert.ToSyslogRFC3164WithCefParam{
		VendorConfig: alert.VendorReflective,
		Hostname:     "test-machine",
		Timestamp:    time.Now().UTC(),
		Priority:     14*8 + 6,
	})
	if err != nil {
		panic(err)
	}

	fmt.Println(cefString)
}
