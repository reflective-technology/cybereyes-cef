package main

import (
	"fmt"
	"time"

	"gitlab.tp.zuso.arpa/zuso-rd-team/go-pkg/events.git/alert"
	"gitlab.tp.zuso.arpa/zuso-rd-team/go-pkg/events.git/helper"
	"gitlab.tp.zuso.arpa/zuso-rd-team/go-pkg/events.git/types"
)

func main() {

	webAlert := alert.WebAlert{
		AlertMetaField: alert.AlertMetaField{
			ID:           "a1b2c3d4-e5f6-7890-abcd-1234567890ab",
			RuleID:       "RULE-12345",
			Name:         "Suspicious Network Activity Detected",
			AlertSubject: "Potential Data Exfiltration Attempt",
			Description:  "Multiple large outbound data transfers detected from internal IP to unknown external destination.",
			Severity:     alert.AlertSeverityCritical,
		},
		WebFields: types.Web{
			Src:           helper.String("192.168.1.1"),
			SrcPort:       helper.String("35098"),
			Dest:          helper.String("192.168.1.2"),
			DestPort:      helper.String("80"),
			HttpMethod:    helper.String("POST"),
			HttpUserAgent: helper.String("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"),
		},
	}

	syslog, err := webAlert.ToSyslogRFC3164WithCef(alert.ToSyslogRFC3164WithCefParam{
		VendorConfig: alert.VendorReflective,
		Hostname:     "web-security-01.zuso.arpa",
		Timestamp:    time.Now().UTC(),
		Priority:     14 * 8,
	})
	if err != nil {
		panic(err)
	}

	fmt.Println(syslog) // <112>Oct 17 20:07:02 web-security-01.zuso.arpa CyberEyes: CEF:0|Reflective|CyberEyes|3|RULE-12345|Suspicious Network Activity Detected|10|dpt=80 dst=192.168.1.2 dvchost=web-security-01.zuso.arpa eventId=a1b2c3d4-e5f6-7890-abcd-1234567890ab requestClientApplication=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36 requestMethod=POST rt=-62135596800000 spt=35098 src=192.168.1.1 cs1=Suspicious Network Activity Detected cs1Label=alertname cs2=critical cs2Label=severity cs3=Potential Data Exfiltration Attempt cs3Label=summary cs4=Multiple large outbound data transfers detected from internal IP to unknown external destination. cs4Label=description
}
