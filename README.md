# Events

This repository contains a collection of event types ,and all the events implemente a method that can convert to a CEF formatted string.

## Usage

To use the events in your project, you can install the package and then import the package into your project.

```go
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
			Status:        helper.String("200"),
			HttpReferrer:  helper.String("http://example.com"),
			UriQuery:      helper.String("param1=value1&param2=value2"),
			UriPath:       helper.String("/path/to/resource"),
			BytesIn:       helper.String("4096"),
			BytesOut:      helper.String("8192"),
			Cookie:        helper.String("testcookie=testvalue"),
			Fingerprint:   helper.String("098f6bcd4621d373cade4e832627b4f6"),
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

	fmt.Println(syslog) // <112>Oct 17 20:21:46 web-security-01.zuso.arpa CyberEyes: CEF:0|Reflective|CyberEyes|3|RULE-12345|Suspicious Network Activity Detected|10|dpt=80 dst=192.168.1.2 dvchost=web-security-01.zuso.arpa eventId=a1b2c3d4-e5f6-7890-abcd-1234567890ab in=4096 out=8192 request=/path/to/resource requestClientApplication=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36 requestContext=http://example.com requestCookies=testcookie\=testvalue requestMethod=POST rt=-62135596800000 spt=35098 src=192.168.1.1 cs1=Suspicious Network Activity Detected cs1Label=alertname cs2=critical cs2Label=severity cs3=Potential Data Exfiltration Attempt cs3Label=summary cs4=Multiple large outbound data transfers detected from internal IP to unknown external destination. cs4Label=description cs5=200 cs5Label=status cs6=param1\=value1&param2\=value2 cs6Label=uri_query CEFingerprint=098f6bcd4621d373cade4e832627b4f6
}

```



## Add new event type


To add new event type, you need to add the json schema to the `json_schemas` directory.

After that, you need to run the following command to generate the event type.

```bash
make codegen
```

and to generate the corresponding alert type, you need to add the event type to the list in `alert/codegen/main.go`

like this:
```
var alertTypes = []any{
	types.AuditdLinux{},
	types.Firewall{},
	types.Ips{},
	types.SysmonWindows{},
	types.WebApplicationFirewall{},
	types.Web{},
	types.WindowsEventsApplication{},
	types.WindowsEventsSecurity{},
}
```

and run `make codegen` again.