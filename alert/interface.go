package alert

import "time"

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
