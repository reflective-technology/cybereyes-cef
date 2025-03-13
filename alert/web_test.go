package alert_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"gitlab.tp.zuso.arpa/zuso-rd-team/go-pkg/events.git/alert"
	"gitlab.tp.zuso.arpa/zuso-rd-team/go-pkg/events.git/helper"
	"gitlab.tp.zuso.arpa/zuso-rd-team/go-pkg/events.git/types"
)

var testWebAlert = alert.WebAlert{
	AlertMetaField: testAlertMeta,
	WebFields: types.Web{
		Src:           helper.String("192.168.1.1"),
		Dest:          helper.String("192.168.1.2"),
		DestPort:      helper.String("80"),
		HttpMethod:    helper.String("GET"),
		HttpReferrer:  helper.String("https://example.com"),
		HttpUserAgent: helper.String("Mozilla/5.0"),
		Status:        helper.String("200"),
		UriPath:       helper.String("/api/v1/login"),
		UriQuery:      helper.String("username=admin&password=admin"),
		BytesIn:       helper.String("1000"),
		BytesOut:      helper.String("2000"),
		Cookie:        helper.String("session=1234567890"),
	},
}

func TestWebAlert_ToCef(t *testing.T) {
	cef, err := testWebAlert.ToCef(alert.ToCefParam{
		VendorConfig: alert.VendorReflective,
		Hostname:     "example.com",
	})
	assert.NoError(t, err)
	assert.NotEmpty(t, cef)
	t.Log(cef)
}
