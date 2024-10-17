package alert_test

import (
	"testing"
	"time"

	"gitlab.tp.zuso.arpa/zuso-rd-team/go-pkg/events.git/alert"
)

var testRawAlert = alert.NewRawAlert(alert.RawAlertParam{
	Meta: alert.AlertMetaField{
		RuleID:       "rule-id-xxx",
		Name:         "Test Alert",
		AlertSubject: "Test Alert Subject",
		Description:  "Test Alert Description",
		Severity:     alert.AlertSeverityLow,
		Timestamp:    time.Unix(1729045128, 576000000).UTC(),
	},
	GeneralFields: map[string]string{
		"src":             "192.168.1.1",
		"dest":            "192.168.1.2",
		"src_port":        "80",
		"dest_port":       "8080",
		"http_method":     "GET",
		"http_referrer":   "http://example.com",
		"url_domain":      "example.com",
		"user":            "testuser",
		"cookie":          "testcookie",
		"http_user_agent": "Mozilla/5.0",
		"xxx":             "x-value",
		"yyy":             "y-value",
	},
}).WithSeverityNum(10)

func TestRawAlert_ToCef(t *testing.T) {
	var testAlert alert.Alert = testRawAlert

	result, err := testAlert.ToCef(alert.ToCefParam{
		VendorConfig: alert.VendorReflective,
		Hostname:     "test-machine",
	})

	if err != nil {
		t.Fatalf("Error generating string: %v", err)
	}

	const expected = "CEF:0|Reflective|CyberEyes|3|rule-id-xxx|Test Alert|10|dhost=example.com dpt=8080 dst=192.168.1.2 dvchost=test-machine requestClientApplication=Mozilla/5.0 requestContext=http://example.com requestCookies=testcookie requestMethod=GET rt=1729045128576 spt=80 src=192.168.1.1 suser=testuser cs1=Test Alert cs1Label=alertname cs2=low cs2Label=severity cs3=Test Alert Subject cs3Label=summary cs4=Test Alert Description cs4Label=description CEXxx=x-value CEYyy=y-value"

	if result != expected {
		t.Errorf("Expected %s, got %s", expected, result)
	}
}

func TestRawAlert_ToSyslogRFC3164WithCef(t *testing.T) {
	var testAlert alert.Alert = testRawAlert

	result, err := testAlert.ToSyslogRFC3164WithCef(alert.ToSyslogRFC3164WithCefParam{
		VendorConfig: alert.VendorReflective,
		Hostname:     "test-machine",
		Timestamp:    time.Unix(1729045128, 576000000).UTC(),
		Priority:     14 * 8,
	})
	if err != nil {
		t.Fatalf("Error generating string: %v", err)
	}

	const expected = "<112>Oct 16 02:18:48 test-machine CyberEyes: CEF:0|Reflective|CyberEyes|3|rule-id-xxx|Test Alert|10|dhost=example.com dpt=8080 dst=192.168.1.2 dvchost=test-machine requestClientApplication=Mozilla/5.0 requestContext=http://example.com requestCookies=testcookie requestMethod=GET rt=1729045128576 spt=80 src=192.168.1.1 suser=testuser cs1=Test Alert cs1Label=alertname cs2=low cs2Label=severity cs3=Test Alert Subject cs3Label=summary cs4=Test Alert Description cs4Label=description CEXxx=x-value CEYyy=y-value"

	if result != expected {
		t.Errorf("Expected %s, got %s", expected, result)
	}
}
