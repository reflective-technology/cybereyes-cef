# cybereyes-cef

A Go library for constructing [Common Event Format (CEF)](https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-8.4/pdfdoc/cef-implementation-standard/cef-implementation-standard.pdf) messages from security alert events. It supports both raw (freeform key-value) alerts and strongly-typed alerts generated from JSON Schemas, and can emit Syslog RFC 3164 messages with CEF payloads.

## Packages

| Package | Description |
|---|---|
| `cefevent` | Low-level CEF event builder, parser, and logger |
| `alert` | High-level alert types (typed and raw) with CEF/Syslog output |
| `types` | Typed event field structs generated from JSON Schemas |

## Supported Event Types

- `AuditdLinux`
- `Firewall`
- `IPS`
- `SysmonWindows`
- `Web`
- `WebApplicationFirewall`
- `WindowsEventsApplication`
- `WindowsEventsSecurity`

## Installation

```bash
go get github.com/reflective-technology/cybereyes-cef
```

## Usage

### Low-level CEF event

Build and print a CEF message directly using the `cefevent` package:

```go
package main

import (
	"fmt"

	"github.com/reflective-technology/cybereyes-cef/cefevent"
)

func main() {
	event := cefevent.NewCefEvent(cefevent.CefEventParams{
		Version:            cefevent.CefVersion0,
		DeviceVendor:       "Cool Vendor",
		DeviceProduct:      "Cool Product",
		DeviceVersion:      "1.0",
		DeviceEventClassId: "FLAKY_EVENT",
		Name:               "Something flaky happened.",
		Severity:           "3",
		Extensions: map[string]string{
			"src":                      "127.0.0.1",
			"requestClientApplication": "Go-http-client/1.1",
		},
	})

	s, err := event.String()
	if err != nil {
		panic(err)
	}
	fmt.Println(s)
	// CEF:0|Cool Vendor|Cool Product|1.0|FLAKY_EVENT|Something flaky happened.|3|requestClientApplication=Go-http-client/1.1 src=127.0.0.1

	// parse a CEF line back into a CefEvent
	line := "CEF:0|Cool Vendor|Cool Product|1.0|COOL_THING|Something cool happened.|Unknown|src=127.0.0.1"
	parsed := cefevent.CefEvent{}
	if _, err := parsed.Read(line); err != nil {
		panic(err)
	}
}
```

### Typed alert (strongly-typed fields)

Use a generated alert struct (e.g. `WebAlert`) for compile-time field safety:

```go
package main

import (
	"fmt"
	"time"

	"github.com/reflective-technology/cybereyes-cef/alert"
	"github.com/reflective-technology/cybereyes-cef/types"
)

func ptr(s string) *string { return &s }

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
			Src:           ptr("192.168.1.1"),
			SrcPort:       ptr("35098"),
			Dest:          ptr("192.168.1.2"),
			DestPort:      ptr("80"),
			HttpMethod:    ptr("POST"),
			HttpUserAgent: ptr("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"),
			Status:        ptr("200"),
			HttpReferrer:  ptr("http://example.com"),
			UriQuery:      ptr("param1=value1&param2=value2"),
			UriPath:       ptr("/path/to/resource"),
			BytesIn:       ptr("4096"),
			BytesOut:      ptr("8192"),
			Cookie:        ptr("testcookie=testvalue"),
			Fingerprint:   ptr("098f6bcd4621d373cade4e832627b4f6"),
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

	fmt.Println(syslog)
	// <112>Apr 27 00:00:00 web-security-01.zuso.arpa CyberEyes: CEF:0|Reflective|CyberEyes|3|RULE-12345|Suspicious Network Activity Detected|10|...
}
```

### Raw alert (freeform key-value fields)

Use `RawAlert` when field names are only known at runtime:

```go
package main

import (
	"fmt"
	"time"

	"github.com/reflective-technology/cybereyes-cef/alert"
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

	syslog, err := rawAlert.ToSyslogRFC3164WithCef(alert.ToSyslogRFC3164WithCefParam{
		VendorConfig: alert.VendorReflective,
		Hostname:     "test-machine",
		Timestamp:    time.Now().UTC(),
		Priority:     14*8 + 6,
	})
	if err != nil {
		panic(err)
	}

	fmt.Println(syslog)
}
```

## Severity Levels

| Constant | Value |
|---|---|
| `AlertSeverityInfo` | `"info"` |
| `AlertSeverityLow` | `"low"` |
| `AlertSeverityMedium` | `"medium"` |
| `AlertSeverityHigh` | `"high"` |
| `AlertSeverityCritical` | `"critical"` |

## Adding a New Event Type

1. Add a JSON Schema file to the `json_schemas/` directory (e.g. `json_schemas/my-event`).
2. Add the new type to the `alertTypes` slice in `alert/codegen/main.go`:

```go
var alertTypes = []any{
	types.AuditdLinux{},
	types.Firewall{},
	types.Ips{},
	types.SysmonWindows{},
	types.WebApplicationFirewall{},
	types.Web{},
	types.WindowsEventsApplication{},
	types.WindowsEventsSecurity{},
	types.MyEvent{}, // new type
}
```

3. Run code generation:

```bash
make codegen
```

This installs `go-jsonschema`, regenerates structs under `types/`, and runs `go generate ./...` to produce the corresponding `alert/` types.

## License

See [LICENSE.md](LICENSE.md).