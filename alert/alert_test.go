package alert_test

import (
	"testing"
	"time"

	"github.com/reflective-technology/cybereyes-cef/alert"
	"github.com/reflective-technology/cybereyes-cef/helper"
	"github.com/reflective-technology/cybereyes-cef/types"
	"github.com/stretchr/testify/assert"
)

var testAlertMeta = alert.AlertMetaField{
	ID:           "id-xxx",
	RuleID:       "rule-id-xxx",
	Name:         "Test Alert",
	AlertSubject: "Test Alert Subject",
	Description:  "Test Alert Description",
	Severity:     alert.AlertSeverityLow,
	Timestamp:    time.Unix(1729045128, 576000000).UTC(),
	SeverityNum:  helper.Int(10),
}

var testRawAlert = alert.NewRawAlert(alert.RawAlertParam{
	Meta: testAlertMeta,
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
})

func TestRawAlert_ToCef(t *testing.T) {
	var testAlert alert.Alert = testRawAlert

	result, err := testAlert.ToCef(alert.ToCefParam{
		VendorConfig: alert.VendorReflective,
		Hostname:     "test-machine",
	})
	assert.NoError(t, err)

	const expected = "CEF:0|Reflective|CyberEyes|3|rule-id-xxx|Test Alert|10|dhost=example.com dpt=8080 dst=192.168.1.2 dvchost=test-machine eventId=id-xxx requestClientApplication=Mozilla/5.0 requestContext=http://example.com requestCookies=testcookie requestMethod=GET rt=1729045128576 spt=80 src=192.168.1.1 suser=testuser cs1=Test Alert cs1Label=alertname cs2=low cs2Label=severity cs3=Test Alert Subject cs3Label=summary cs4=Test Alert Description cs4Label=description CEXxx=x-value CEYyy=y-value"

	assert.Equal(t, expected, result)
}

func TestRawAlert_ToSyslogRFC3164WithCef(t *testing.T) {
	var testAlert alert.Alert = testRawAlert

	result, err := testAlert.ToSyslogRFC3164WithCef(alert.ToSyslogRFC3164WithCefParam{
		VendorConfig: alert.VendorReflective,
		Hostname:     "test-machine",
		Timestamp:    time.Unix(1729045128, 576000000).UTC(),
		Priority:     14 * 8,
	})
	assert.NoError(t, err)

	const expected = "<112>Oct 16 02:18:48 test-machine CyberEyes: CEF:0|Reflective|CyberEyes|3|rule-id-xxx|Test Alert|10|dhost=example.com dpt=8080 dst=192.168.1.2 dvchost=test-machine eventId=id-xxx requestClientApplication=Mozilla/5.0 requestContext=http://example.com requestCookies=testcookie requestMethod=GET rt=1729045128576 spt=80 src=192.168.1.1 suser=testuser cs1=Test Alert cs1Label=alertname cs2=low cs2Label=severity cs3=Test Alert Subject cs3Label=summary cs4=Test Alert Description cs4Label=description CEXxx=x-value CEYyy=y-value"
	assert.Equal(t, expected, result)
}

func TestGeneratedAlertType_ToCef(t *testing.T) {
	var testAlert alert.Alert = &alert.WebAlert{
		AlertMetaField: testAlertMeta,
		WebFields: types.Web{
			Src:           helper.String("192.168.1.1"),
			Dest:          helper.String("192.168.1.2"),
			DestPort:      helper.String("443"),
			Status:        helper.String("200"),
			HttpMethod:    helper.String("GET"),
			HttpUserAgent: helper.String("Mozilla/5.0"),
			HttpReferrer:  helper.String("http://example.com"),
			UriQuery:      helper.String("param1=value1&param2=value2"),
			UriPath:       helper.String("/path/to/resource"),
			BytesIn:       helper.String("4096"),
			BytesOut:      helper.String("8192"),
			Cookie:        helper.String("testcookie=testvalue"),
		},
	}

	result, err := testAlert.ToCef(alert.ToCefParam{
		VendorConfig: alert.VendorReflective,
		Hostname:     "test-machine",
	})
	assert.NoError(t, err)

	const expected = `CEF:0|Reflective|CyberEyes|3|rule-id-xxx|Test Alert|10|dpt=443 dst=192.168.1.2 dvchost=test-machine eventId=id-xxx in=4096 out=8192 request=/path/to/resource requestClientApplication=Mozilla/5.0 requestContext=http://example.com requestCookies=testcookie\=testvalue requestMethod=GET rt=1729045128576 src=192.168.1.1 cs1=Test Alert cs1Label=alertname cs2=low cs2Label=severity cs3=Test Alert Subject cs3Label=summary cs4=Test Alert Description cs4Label=description cs5=200 cs5Label=status cs6=param1\=value1&param2\=value2 cs6Label=uri_query`
	assert.Equal(t, expected, result)

}
