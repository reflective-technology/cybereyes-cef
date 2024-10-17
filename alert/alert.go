package alert

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"gitlab.tp.zuso.arpa/zuso-rd-team/go-pkg/events.git/cefevent"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

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

type RawAlert struct {
	Meta AlertMetaField

	// will be translated into extensions
	generalFields map[string]string
}

type RawAlertParam struct {
	Meta          AlertMetaField
	GeneralFields map[string]string
}

func NewRawAlert(param RawAlertParam) *RawAlert {
	alert := RawAlert{
		Meta:          param.Meta,
		generalFields: param.GeneralFields,
	}

	return &alert
}

// ToCEF converts the alert to CEF format
// there are three segments in the CEF format
// 1. cef standard fields
// 2. custom labels and values
// 3. user defined fields
func (alert *RawAlert) ToCef(param ToCefParam) (string, error) {
	extensions := make(map[string]string)
	{
		// add standard fields from alert meta
		extensions["rt"] = fmt.Sprintf("%d", alert.Meta.Timestamp.UnixMilli())
		extensions["dvchost"] = param.Hostname

		// add custom fields from alert meta
		extensions["cs1Label"] = "alertname"
		extensions["cs1"] = alert.Meta.Name

		extensions["cs2Label"] = "severity"
		extensions["cs2"] = string(alert.Meta.Severity)

		extensions["cs3Label"] = "summary"
		extensions["cs3"] = alert.Meta.AlertSubject

		extensions["cs4Label"] = "description"
		extensions["cs4"] = alert.Meta.Description

		// add custom fields from GeneralFields
		if status, ok := alert.generalFields["status"]; ok {
			extensions["cs5Label"] = "status"
			extensions["cs5"] = status
		}
		if uriQuery, ok := alert.generalFields["uri_query"]; ok {
			extensions["cs6Label"] = "uri_query"
			extensions["cs6"] = uriQuery
		}

		for k, v := range alert.generalFields {
			// skip status and uri_query because they are already included in custom fields
			if k == "status" || k == "uri_query" {
				continue
			}

			// add cef standard fields
			transformedKey, ok := generalFieldsToCefStandardFieldsMap[k]
			if ok {
				extensions[transformedKey] = v
				continue
			}

			// add user defined fields
			transformedKey, err := UserDefinedFieldName(k, param.VendorConfig.Abbreviation)
			if err == nil {
				extensions[transformedKey] = v
				continue
			}
		}
	}

	severity, err := ResolveCEFSeverity(alert.Meta)
	if err != nil {
		return "", err
	}

	event := cefevent.NewCefEvent(cefevent.CefEventParams{
		Version:               cefevent.CefVersion0,
		DeviceVendor:          param.VendorConfig.VendorName,
		DeviceProduct:         param.VendorConfig.ProductName,
		DeviceVersion:         param.VendorConfig.ProductVersion,
		DeviceEventClassId:    alert.Meta.RuleID,
		Name:                  alert.Meta.Name,
		Severity:              severity,
		Extensions:            extensions,
		ExtensionsKeySortFunc: VendorBasedExtensionsKeySortFunc(param.VendorConfig),
	})

	return event.String()
}

func (alert *RawAlert) ToSyslogRFC3164WithCef(param ToSyslogRFC3164WithCefParam) (string, error) {

	msg, err := alert.ToCef(ToCefParam{
		VendorConfig: param.VendorConfig,
		Hostname:     param.Hostname,
	})
	if err != nil {
		return "", err
	}

	result := fmt.Sprintf("<%d>%s %s %s: %s", param.Priority, param.Timestamp.Format(time.Stamp), param.Hostname, param.VendorConfig.ProductName, msg)
	return result, nil
}

// Convert the field name to camel case and prefix with vendor abbreviation
func UserDefinedFieldName(name string, vendorAbbreviation string) (string, error) {
	if name == "" {
		return "", errors.New("given field name is empty")
	}

	words := strings.Split(name, "_")
	if len(words) == 0 {
		return "", errors.New("given field name is invalid")
	}

	caser := cases.Title(language.Und)
	for i := 0; i < len(words); i++ {
		words[i] = caser.String(words[i])
	}

	// Join words and prefix with vendor abbreviation
	titleCase := strings.Join(words, "")
	return vendorAbbreviation + titleCase, nil
}

// ResolveSeverity converts the alert severity to CEF severity header field
//
// According to cef-implementation-standard.pdf (https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-8.4/pdfdoc/cef-implementation-standard/cef-implementation-standard.pdf_
// agentSeverity is a string or integer and it reflects the importance of the event.
// - The valid string values are: Unknown, Low, Medium, High, and Very-High.
// - The valid integer values are: 0-3=Low, 4-6=Medium, 7-8=High, and 9-10=Very-High.
func ResolveCEFSeverity(meta AlertMetaField) (string, error) {
	var point int

	if meta.SeverityNum != nil {
		point = *meta.SeverityNum
		return fmt.Sprintf("%d", point), nil
	}

	if meta.Severity == "" {
		return "", errors.New("both Severity and SeverityNum are not set")
	}

	point, err := DefaultSeverityPoint(string(meta.Severity))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d", point), nil
}

// this function take the intersection of cef standard severity point and general fields severity point as the default severity point
// cef standard severity point: 0-3=Low, 4-6=Medium, 7-8=High, and 9-10=Very-High.
// general fields severity point: 1=info, 2=low, 3,4,5,6,7=medium, 8,9=high, 10=critical
func DefaultSeverityPoint(severity string) (int, error) {
	switch severity {
	case "info":
		return 0, nil
	case "low":
		return 2, nil
	case "medium":
		return 5, nil
	case "high":
		return 8, nil
	case "critical":
		return 10, nil
	default:
		return 0, fmt.Errorf("unknown severity: %s", severity)
	}
}
