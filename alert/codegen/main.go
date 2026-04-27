package main

import (
	_ "embed"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"strings"

	"log"
	"text/template"

	"github.com/reflective-technology/cybereyes-cef/alert"
	"github.com/reflective-technology/cybereyes-cef/types"
)

//go:embed alert.tmpl
var alertTemplate string

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

type AlertStructData struct {
	LogTypeName       string
	UserDefinedFields []*AlertField
	StandardCefFields []*StandardCefFields
	HaveStatusField   bool
	HaveUriQueryField bool
}

type AlertField struct {
	StructName string
	JsonName   string
}

type StandardCefFields struct {
	*AlertField
	StandardFieldName string
}

type FieldsFilter func(field *AlertField) bool

func FilterOutFieldsWithJsonTags(jsonTags ...string) FieldsFilter {
	return func(field *AlertField) bool {
		for _, tag := range jsonTags {
			if field.JsonName == tag {
				return false
			}
		}
		return true
	}
}

func ListAlertFields(alertType any, filters ...FieldsFilter) []*AlertField {
	fields := []*AlertField{}

	alertReflectType := reflect.TypeOf(alertType)
NextField:
	for i := 0; i < alertReflectType.NumField(); i++ {
		field := alertReflectType.Field(i)
		jsonTag := regexp.MustCompile(`^([^,]+)`).FindString(field.Tag.Get("json"))

		alertField := AlertField{
			StructName: field.Name,
			JsonName:   jsonTag,
		}

		// Declare the label here
		for _, filter := range filters {
			if !filter(&alertField) {
				continue NextField
			}
		}

		fields = append(fields, &alertField)
	}

	return fields
}

func RunTemplate(data AlertStructData, outputDir string) error {
	tmpl, err := template.New("alert.tmpl").Parse(alertTemplate)
	if err != nil {
		return err
	}

	file_name := fmt.Sprintf("%s/%s.go", outputDir, strings.ToLower(regexp.MustCompile(`([a-z0-9])([A-Z])`).ReplaceAllString(data.LogTypeName, "${1}_${2}")))
	file, err := os.Create(file_name)
	if err != nil {
		return err
	}
	defer file.Close()

	if err := tmpl.ExecuteTemplate(file, "AlertStruct", data); err != nil {
		return err
	}

	return nil
}

func main() {
	const outputDir = "."

	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		log.Fatalf("Error creating output directory: %v", err)
	}

	for _, alertType := range alertTypes {
		allFields := ListAlertFields(alertType, FilterOutFieldsWithJsonTags("tags"))
		userDefinedFields := []*AlertField{}
		standardCefFields := []*StandardCefFields{}
		haveStatusField := false
		haveUriQueryField := false

		for _, field := range allFields {
			if field.JsonName == "status" {
				haveStatusField = true
				continue
			}
			if field.JsonName == "uri_query" {
				haveUriQueryField = true
				continue
			}

			if standardCefField, ok := alert.MapGeneralFieldsToCefStandardFields(field.JsonName); ok {
				standardCefFields = append(standardCefFields, &StandardCefFields{
					AlertField:        field,
					StandardFieldName: standardCefField,
				})
			} else {
				userDefinedFields = append(userDefinedFields, field)
			}
		}

		data := AlertStructData{
			LogTypeName:       reflect.TypeOf(alertType).Name(),
			UserDefinedFields: userDefinedFields,
			StandardCefFields: standardCefFields,
			HaveStatusField:   haveStatusField,
			HaveUriQueryField: haveUriQueryField,
		}

		if err := RunTemplate(data, outputDir); err != nil {
			log.Fatalf("Error running template: %v", err)
		}
	}
}
