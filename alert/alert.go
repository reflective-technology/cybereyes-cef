package alert

//go:generate go run codegen/main.go

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
	// alert_id
	ID string

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
	return ResolveCef(
		alert.Meta, param.VendorConfig,
		EnhanceExtensionsWithHostname(param.Hostname),
		EnhanceExtensionsWithAlertMeta(alert.Meta),
		EnhanceExtensionsFromGeneralFields(alert.generalFields, param.VendorConfig.Abbreviation),
	)
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

var (
	ErrExtensionIsNil = errors.New("extension is nil")
)

type ExtensionsPipeline func(extensions map[string]string) error

func EnhanceExtensionsWithAlertMeta(meta AlertMetaField) ExtensionsPipeline {
	return func(extension map[string]string) error {
		if extension == nil {
			return ErrExtensionIsNil
		}

		// add standard fields from alert meta
		extension["rt"] = fmt.Sprintf("%d", meta.Timestamp.UnixMilli())
		extension["eventId"] = meta.ID

		// add custom fields from alert meta
		extension["cs1Label"] = "alertname"
		extension["cs1"] = meta.Name

		extension["cs2Label"] = "severity"
		extension["cs2"] = string(meta.Severity)

		extension["cs3Label"] = "summary"
		extension["cs3"] = meta.AlertSubject

		extension["cs4Label"] = "description"
		extension["cs4"] = meta.Description

		return nil
	}
}

func EnhanceExtensionsWithHostname(hostname string) ExtensionsPipeline {
	return func(extensions map[string]string) error {
		if extensions == nil {
			return ErrExtensionIsNil
		}

		extensions["dvchost"] = hostname
		return nil
	}
}

func EnhanceExtensionsFromGeneralFields(generalFields map[string]string, vendorAbbreviation string) ExtensionsPipeline {
	return func(extensions map[string]string) error {
		if extensions == nil {
			return ErrExtensionIsNil
		}

		// add custom fields from GeneralFields
		if status, ok := generalFields["status"]; ok {
			extensions["cs5Label"] = "status"
			extensions["cs5"] = status
		}
		if uriQuery, ok := generalFields["uri_query"]; ok {
			extensions["cs6Label"] = "uri_query"
			extensions["cs6"] = uriQuery
		}

		for k, v := range generalFields {
			// skip status and uri_query because they are already included in custom fields
			if k == "status" || k == "uri_query" {
				continue
			}

			// add cef standard fields
			transformedKey, ok := MapGeneralFieldsToCefStandardFields(k)
			if ok {
				extensions[transformedKey] = v
				continue
			}

			// add user defined fields
			transformedKey, err := UserDefinedFieldName(k, vendorAbbreviation)
			if err == nil {
				extensions[transformedKey] = v
				continue
			}
		}

		return nil
	}
}

func ResolveCef(alertMeta AlertMetaField, vendorConfig VendorConfig, pipelines ...ExtensionsPipeline) (string, error) {
	extension := make(map[string]string)
	for _, pipeline := range pipelines {
		if err := pipeline(extension); err != nil {
			return "", err
		}
	}

	severity, err := ResolveCEFSeverity(alertMeta)
	if err != nil {
		return "", err
	}

	event := cefevent.NewCefEvent(cefevent.CefEventParams{
		Version:               cefevent.CefVersion0,
		DeviceVendor:          vendorConfig.VendorName,
		DeviceProduct:         vendorConfig.ProductName,
		DeviceVersion:         vendorConfig.ProductVersion,
		DeviceEventClassId:    alertMeta.RuleID,
		Name:                  alertMeta.Name,
		Severity:              severity,
		Extensions:            extension,
		ExtensionsKeySortFunc: VendorBasedExtensionsKeySortFunc(vendorConfig),
	})

	return event.String()
}

func SyslogRFC3164WithCef(alert Alert, param ToSyslogRFC3164WithCefParam) (string, error) {

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
