package cefevent_test

import (
	"reflect"
	"testing"

	"gitlab.tp.zuso.arpa/zuso-rd-team/go-pkg/cef.git/cefevent"
)

var defaultParams = cefevent.CefEventParams{
	Version:               cefevent.CefVersion0,
	DeviceVendor:          "Cool Vendor",
	DeviceProduct:         "Cool Product",
	DeviceVersion:         "1.0",
	DeviceEventClassId:    "COOL_THING",
	Name:                  "Something cool happened.",
	Severity:              "Unknown",
	Extensions:            map[string]string{"src": "127.0.0.1"},
	ExtensionsKeySortFunc: nil,
}

var eventLine = "CEF:0|Cool Vendor|Cool Product|1.0|COOL_THING|Something cool happened.|Unknown|src=127.0.0.1"

func TestCefEventExpected(t *testing.T) {

	expectedEvent := cefevent.NewCefEvent(defaultParams)

	want := "CEF:0|Cool Vendor|Cool Product|1.0|COOL_THING|Something cool happened.|Unknown|src=127.0.0.1"
	got, _ := expectedEvent.String()

	if want != got {
		t.Errorf("event.String() = %q, want %q", got, want)
	}

}

func TestCefEventParsed(t *testing.T) {

	newEvent := cefevent.NewCefEvent(cefevent.CefEventParams{})
	want := cefevent.NewCefEvent(defaultParams)
	got, err := newEvent.Read(eventLine)
	if err != nil {
		t.Errorf("read failed: %v", err)
	}

	if !reflect.DeepEqual(want, got) {
		t.Errorf("Parse() = %v, want %v", got, want)
	}
}

func TestCefEventParsedAndGenerated(t *testing.T) {

	newEvent := cefevent.NewCefEvent(cefevent.CefEventParams{})
	want := eventLine
	parsedEvent, _ := newEvent.Read(eventLine)
	got, _ := parsedEvent.String()

	if !reflect.DeepEqual(want, got) {
		t.Errorf("Parse() = %v, want %v", got, want)
	}
}

func TestCefEventParsedFail(t *testing.T) {

	newEvent := cefevent.CefEvent{}

	got, err := newEvent.Read("This should definitely fail.")

	if err == nil {
		t.Errorf("Parse() = %v, want %v", err, got)
	}
}

func TestCefEventEscape(t *testing.T) {

	extLocal := make(map[string]string)
	extLocal["broken_src\\"] = "\n127.0.0.2="

	params := defaultParams
	params.DeviceVendor = "\\Cool\nVendor|"
	params.Extensions = extLocal

	borkyEvent := cefevent.NewCefEvent(params)

	want := "CEF:0|\\\\Cool\\nVendor\\||Cool Product|1.0|COOL_THING|Something cool happened.|Unknown|broken_src\\\\=\\n127.0.0.2\\="
	got, _ := borkyEvent.String()

	if want != got {
		t.Errorf("event.String() = %q, want %q", got, want)
	}

}

func TestCefEventMandatoryVersionField(t *testing.T) {

	params := defaultParams
	params.DeviceVendor = ""

	brokenEvent := cefevent.NewCefEvent(params)
	_, err := brokenEvent.String()

	if err == nil {
		t.Errorf("%v", err)
	}
}

func TestCefEventMandatoryDeviceVendorField(t *testing.T) {

	params := defaultParams
	params.DeviceVendor = ""

	brokenEvent := cefevent.NewCefEvent(params)
	_, err := brokenEvent.String()

	if err == nil {
		t.Errorf("%v", err)
	}
}

func TestCefEventMandatoryDeviceProductField(t *testing.T) {

	params := defaultParams
	params.DeviceProduct = ""

	brokenEvent := cefevent.NewCefEvent(params)
	_, err := brokenEvent.String()

	if err == nil {
		t.Errorf("%v", err)
	}
}

func TestCefEventMandatoryDeviceVersionField(t *testing.T) {

	params := defaultParams
	params.DeviceVersion = ""

	brokenEvent := cefevent.NewCefEvent(params)
	_, err := brokenEvent.String()

	if err == nil {
		t.Errorf("%v", err)
	}
}

func TestCefEventMandatoryDeviceEventClassIdField(t *testing.T) {

	params := defaultParams
	params.DeviceEventClassId = ""

	brokenEvent := cefevent.NewCefEvent(params)
	_, err := brokenEvent.String()

	if err == nil {
		t.Errorf("%v", err)
	}
}

func TestCefEventMandatoryNameField(t *testing.T) {

	params := defaultParams
	params.Name = ""

	brokenEvent := cefevent.NewCefEvent(params)
	_, err := brokenEvent.String()

	if err == nil {
		t.Errorf("%v", err)
	}
}

func TestCefEventMandatorySeverityField(t *testing.T) {

	params := defaultParams
	params.Severity = ""

	brokenEvent := cefevent.NewCefEvent(params)
	_, err := brokenEvent.String()

	if err == nil {
		t.Errorf("%v", err)
	}
}

func someImplementationOfCefEventer(e cefevent.CefEventer) error {
	return e.Validate()
}

func TestCefEventerValidate(t *testing.T) {
	event := cefevent.NewCefEvent(defaultParams)
	if someImplementationOfCefEventer(event) != nil {
		t.Errorf("Validation should be succesful here.")
	}

	params := defaultParams
	params.DeviceVendor = ""

	noDeviceVendor := cefevent.NewCefEvent(params)
	if someImplementationOfCefEventer(noDeviceVendor) == nil {
		t.Errorf("Validation should fail here.")
	}
}

func TestCefEventerLoggingSuccess(t *testing.T) {
	event := cefevent.NewCefEvent(defaultParams)
	err := event.Log()

	if err != nil {
		t.Errorf("%v", err)
	}
}

func TestCefEventerLoggingFail(t *testing.T) {

	params := defaultParams
	params.DeviceVendor = ""

	brokenEvent := cefevent.NewCefEvent(params)
	err := brokenEvent.Log()

	if err == nil {
		t.Errorf("%v", err)
	}
}

func TestCefEvent_ToJSON(t *testing.T) {
	var tests = []struct {
		cev      *cefevent.CefEvent
		want     string
		hasError bool
	}{
		{
			cev: cefevent.NewCefEvent(cefevent.CefEventParams{
				Version:            1,
				DeviceVendor:       "Test Vendor",
				DeviceProduct:      "Test Product",
				DeviceVersion:      "1.0.0",
				DeviceEventClassId: "Test Class ID",
				Name:               "Test Name",
				Severity:           "Test Severity",
				Extensions:         map[string]string{"Extension1": "Value1", "Extension2": "Value2"},
			}),
			want:     `{"Version":1,"DeviceVendor":"Test Vendor","DeviceProduct":"Test Product","DeviceVersion":"1.0.0","DeviceEventClassId":"Test Class ID","Name":"Test Name","Severity":"Test Severity","Extensions":{"Extension1":"Value1","Extension2":"Value2"}}`,
			hasError: false,
		},
		{
			cev: cefevent.NewCefEvent(cefevent.CefEventParams{
				Version:            1,
				DeviceVendor:       "",
				DeviceProduct:      "Test Product",
				DeviceVersion:      "1.0.0",
				DeviceEventClassId: "Test Class ID",
				Name:               "Test Name",
				Severity:           "Test Severity",
				Extensions:         map[string]string{"Extension1": "Value1", "Extension2": "Value2"},
			}),
			want:     "",
			hasError: true,
		},
	}

	for _, tt := range tests {
		got, err := tt.cev.ToJSON()
		if (err != nil) != tt.hasError {
			t.Errorf("Expected error status: %v, got: %v", tt.hasError, err)
		}
		if got != tt.want {
			t.Errorf("Expected json `%v`, but got `%v`", tt.want, got)
		}
	}
}
