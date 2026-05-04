package alert_test

import (
	"testing"
	"time"

	"github.com/reflective-technology/cybereyes-cef/v3/alert"
	"github.com/reflective-technology/cybereyes-cef/v3/types"
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
	SeverityNum:  new(10),
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
			Src:           new("192.168.1.1"),
			Dest:          new("192.168.1.2"),
			DestPort:      new("443"),
			Status:        new("200"),
			HttpMethod:    new("GET"),
			HttpUserAgent: new("Mozilla/5.0"),
			HttpReferrer:  new("http://example.com"),
			UriQuery:      new("param1=value1&param2=value2"),
			UriPath:       new("/path/to/resource"),
			BytesIn:       new("4096"),
			BytesOut:      new("8192"),
			Cookie:        new("testcookie=testvalue"),
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

func TestResolveCEFSeverity(t *testing.T) {
	cases := []struct {
		name    string
		meta    alert.AlertMetaField
		want    string
		wantErr bool
	}{
		{
			name: "info severity string",
			meta: alert.AlertMetaField{Severity: alert.AlertSeverityInfo},
			want: "0",
		},
		{
			name: "low severity string",
			meta: alert.AlertMetaField{Severity: alert.AlertSeverityLow},
			want: "2",
		},
		{
			name: "medium severity string",
			meta: alert.AlertMetaField{Severity: alert.AlertSeverityMedium},
			want: "5",
		},
		{
			name: "high severity string",
			meta: alert.AlertMetaField{Severity: alert.AlertSeverityHigh},
			want: "8",
		},
		{
			name: "critical severity string",
			meta: alert.AlertMetaField{Severity: alert.AlertSeverityCritical},
			want: "10",
		},
		{
			name: "severity num overrides severity string",
			meta: alert.AlertMetaField{Severity: alert.AlertSeverityLow, SeverityNum: new(7)},
			want: "7",
		},
		{
			name: "severity num zero is valid",
			meta: alert.AlertMetaField{Severity: alert.AlertSeverityHigh, SeverityNum: new(0)},
			want: "0",
		},
		{
			name:    "both empty returns error",
			meta:    alert.AlertMetaField{},
			wantErr: true,
		},
		{
			name:    "unknown severity string returns error",
			meta:    alert.AlertMetaField{Severity: "unknown"},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := alert.ResolveCEFSeverity(tc.meta)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestDefaultSeverityPoint(t *testing.T) {
	cases := []struct {
		severity string
		want     int
		wantErr  bool
	}{
		{"info", 0, false},
		{"low", 2, false},
		{"medium", 5, false},
		{"high", 8, false},
		{"critical", 10, false},
		{"unknown", 0, true},
		{"", 0, true},
	}

	for _, tc := range cases {
		t.Run(tc.severity, func(t *testing.T) {
			got, err := alert.DefaultSeverityPoint(tc.severity)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestUserDefinedFieldName(t *testing.T) {
	cases := []struct {
		name    string
		field   string
		vendor  string
		want    string
		wantErr bool
	}{
		{"single word", "field", "CE", "CEField", false},
		{"two words snake_case", "my_field", "CE", "CEMyField", false},
		{"three words snake_case", "multi_word_field", "CE", "CEMultiWordField", false},
		{"empty vendor abbreviation", "field", "", "Field", false},
		{"empty field name returns error", "", "CE", "", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := alert.UserDefinedFieldName(tc.field, tc.vendor)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestEnhanceExtensionsWithAlertMeta(t *testing.T) {
	ext := make(map[string]string)
	err := alert.EnhanceExtensionsWithAlertMeta(testAlertMeta)(ext)
	assert.NoError(t, err)

	assert.Equal(t, "1729045128576", ext["rt"])
	assert.Equal(t, "id-xxx", ext["eventId"])
	assert.Equal(t, "alertname", ext["cs1Label"])
	assert.Equal(t, "Test Alert", ext["cs1"])
	assert.Equal(t, "severity", ext["cs2Label"])
	assert.Equal(t, "low", ext["cs2"])
	assert.Equal(t, "summary", ext["cs3Label"])
	assert.Equal(t, "Test Alert Subject", ext["cs3"])
	assert.Equal(t, "description", ext["cs4Label"])
	assert.Equal(t, "Test Alert Description", ext["cs4"])
}

func TestEnhanceExtensionsWithAlertMeta_NilMapError(t *testing.T) {
	err := alert.EnhanceExtensionsWithAlertMeta(testAlertMeta)(nil)
	assert.ErrorIs(t, err, alert.ErrExtensionIsNil)
}

func TestEnhanceExtensionsWithHostname(t *testing.T) {
	ext := make(map[string]string)
	err := alert.EnhanceExtensionsWithHostname("my-host")(ext)
	assert.NoError(t, err)
	assert.Equal(t, "my-host", ext["dvchost"])
}

func TestEnhanceExtensionsWithHostname_NilMapError(t *testing.T) {
	err := alert.EnhanceExtensionsWithHostname("my-host")(nil)
	assert.ErrorIs(t, err, alert.ErrExtensionIsNil)
}

func TestEnhanceExtensionsFromGeneralFields(t *testing.T) {
	t.Run("status is mapped to cs5", func(t *testing.T) {
		ext := make(map[string]string)
		err := alert.EnhanceExtensionsFromGeneralFields(map[string]string{"status": "404"}, "CE")(ext)
		assert.NoError(t, err)
		assert.Equal(t, "404", ext["cs5"])
		assert.Equal(t, "status", ext["cs5Label"])
	})

	t.Run("uri_query is mapped to cs6", func(t *testing.T) {
		ext := make(map[string]string)
		err := alert.EnhanceExtensionsFromGeneralFields(map[string]string{"uri_query": "page=1&limit=10"}, "CE")(ext)
		assert.NoError(t, err)
		assert.Equal(t, "page=1&limit=10", ext["cs6"])
		assert.Equal(t, "uri_query", ext["cs6Label"])
	})

	t.Run("standard CEF fields are mapped", func(t *testing.T) {
		ext := make(map[string]string)
		err := alert.EnhanceExtensionsFromGeneralFields(map[string]string{
			"src":      "10.0.0.1",
			"dest":     "10.0.0.2",
			"src_port": "1234",
			"user":     "admin",
		}, "CE")(ext)
		assert.NoError(t, err)
		assert.Equal(t, "10.0.0.1", ext["src"])
		assert.Equal(t, "10.0.0.2", ext["dst"])
		assert.Equal(t, "1234", ext["spt"])
		assert.Equal(t, "admin", ext["suser"])
	})

	t.Run("user-defined fields get vendor prefix", func(t *testing.T) {
		ext := make(map[string]string)
		err := alert.EnhanceExtensionsFromGeneralFields(map[string]string{
			"custom_field": "value1",
			"another":      "value2",
		}, "CE")(ext)
		assert.NoError(t, err)
		assert.Equal(t, "value1", ext["CECustomField"])
		assert.Equal(t, "value2", ext["CEAnother"])
	})

	t.Run("nil map returns error", func(t *testing.T) {
		err := alert.EnhanceExtensionsFromGeneralFields(map[string]string{}, "CE")(nil)
		assert.ErrorIs(t, err, alert.ErrExtensionIsNil)
	})
}

func TestRawAlert_ToCef_NoGeneralFields(t *testing.T) {
	rawAlert := alert.NewRawAlert(alert.RawAlertParam{
		Meta:          testAlertMeta,
		GeneralFields: map[string]string{},
	})

	result, err := rawAlert.ToCef(alert.ToCefParam{
		VendorConfig: alert.VendorReflective,
		Hostname:     "test-machine",
	})
	assert.NoError(t, err)

	const expected = "CEF:0|Reflective|CyberEyes|3|rule-id-xxx|Test Alert|10|dvchost=test-machine eventId=id-xxx rt=1729045128576 cs1=Test Alert cs1Label=alertname cs2=low cs2Label=severity cs3=Test Alert Subject cs3Label=summary cs4=Test Alert Description cs4Label=description"
	assert.Equal(t, expected, result)
}

func TestRawAlert_ToCef_SeverityStringFallback(t *testing.T) {
	// When SeverityNum is nil, the Severity string is used for the CEF header.
	metaMedium := alert.AlertMetaField{
		ID:           "id-xxx",
		RuleID:       "rule-id-xxx",
		Name:         "Test Alert",
		AlertSubject: "Test Alert Subject",
		Description:  "Test Alert Description",
		Severity:     alert.AlertSeverityMedium,
		Timestamp:    time.Unix(1729045128, 576000000).UTC(),
	}
	rawAlert := alert.NewRawAlert(alert.RawAlertParam{
		Meta:          metaMedium,
		GeneralFields: map[string]string{},
	})

	result, err := rawAlert.ToCef(alert.ToCefParam{
		VendorConfig: alert.VendorReflective,
		Hostname:     "test-machine",
	})
	assert.NoError(t, err)

	const expected = "CEF:0|Reflective|CyberEyes|3|rule-id-xxx|Test Alert|5|dvchost=test-machine eventId=id-xxx rt=1729045128576 cs1=Test Alert cs1Label=alertname cs2=medium cs2Label=severity cs3=Test Alert Subject cs3Label=summary cs4=Test Alert Description cs4Label=description"
	assert.Equal(t, expected, result)
}

func TestRawAlert_ToCef_SeverityNumOverride(t *testing.T) {
	// SeverityNum=3 overrides AlertSeverityCritical in the CEF header;
	// cs2 still reflects the Severity string ("critical").
	metaOverride := alert.AlertMetaField{
		ID:           "id-xxx",
		RuleID:       "rule-id-xxx",
		Name:         "Test Alert",
		AlertSubject: "Test Alert Subject",
		Description:  "Test Alert Description",
		Severity:     alert.AlertSeverityCritical,
		SeverityNum:  new(3),
		Timestamp:    time.Unix(1729045128, 576000000).UTC(),
	}
	rawAlert := alert.NewRawAlert(alert.RawAlertParam{
		Meta:          metaOverride,
		GeneralFields: map[string]string{},
	})

	result, err := rawAlert.ToCef(alert.ToCefParam{
		VendorConfig: alert.VendorReflective,
		Hostname:     "test-machine",
	})
	assert.NoError(t, err)

	const expected = "CEF:0|Reflective|CyberEyes|3|rule-id-xxx|Test Alert|3|dvchost=test-machine eventId=id-xxx rt=1729045128576 cs1=Test Alert cs1Label=alertname cs2=critical cs2Label=severity cs3=Test Alert Subject cs3Label=summary cs4=Test Alert Description cs4Label=description"
	assert.Equal(t, expected, result)
}
