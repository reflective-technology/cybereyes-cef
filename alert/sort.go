package alert

import (
	"regexp"
	"sort"
	"strings"
)

var (
	csLabelRegex = regexp.MustCompile(`^cs\d(Label)?$`)
)

// Define priority levels for different field types
func VendorBasedPriority(field string, vendorAbbreviation string) int {
	if csLabelRegex.MatchString(field) {
		return 1 // custom string fields are followed by the standard fields
	}
	if strings.HasPrefix(field, vendorAbbreviation) {
		return 2 // vendor specific fields are in the end
	}
	return 0 // standard fields are in the front
}

func VendorBasedExtensionsKeySortFunc(vendorConfig VendorConfig) func(keys []string) {
	return func(keys []string) {
		sort.Slice(keys, func(i, j int) bool {

			// Get priorities for both fields
			iPriority := VendorBasedPriority(keys[i], vendorConfig.Abbreviation)
			jPriority := VendorBasedPriority(keys[j], vendorConfig.Abbreviation)

			// If priorities are different, sort by priority
			if iPriority != jPriority {
				return iPriority < jPriority
			}

			// If priorities are the same, sort alphabetically
			return keys[i] < keys[j]
		})
	}
}
