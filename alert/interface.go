package alert

import "time"

type AlertSeverity string

const (
	AlertSeverityInfo     AlertSeverity = "info"
	AlertSeverityLow      AlertSeverity = "low"
	AlertSeverityMedium   AlertSeverity = "medium"
	AlertSeverityHigh     AlertSeverity = "high"
	AlertSeverityCritical AlertSeverity = "critical"
)

type AlertMetaField struct {
	// rule_id
	RuleID string

	// name
	Name string

	// alert_subject
	AlertSubject string

	// alert_desc
	Description string

	// severity
	Severity AlertSeverity

	// severity_num
	SeverityNum *int

	// @timestamp
	Timestamp time.Time
}

type Alert interface {
	ToSyslogRFC3164WithCef(param ToSyslogRFC3164WithCefParam) (string, error)
	ToCef(param ToCefParam) (string, error)
}

type ToSyslogRFC3164WithCefParam struct {
	VendorConfig VendorConfig
	Hostname     string
	Timestamp    time.Time
	Priority     uint8
}

type ToCefParam struct {
	VendorConfig VendorConfig
	Hostname     string
}
