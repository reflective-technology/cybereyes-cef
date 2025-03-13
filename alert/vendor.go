package alert

type VendorConfig struct {
	VendorName     string
	ProductName    string
	ProductVersion string
	Abbreviation   string
}

var (
	VendorReflective VendorConfig = VendorConfig{
		VendorName:     "Reflective",
		ProductName:    "CyberEyes",
		ProductVersion: "3",
		Abbreviation:   "CE",
	}
	VendorArray VendorConfig = VendorConfig{
		VendorName:     "Array Networks",
		ProductName:    "Insighter",
		ProductVersion: "3",
		Abbreviation:   "INST",
	}
)
