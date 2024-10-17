package alert

var (
	generalFieldsToCefStandardFieldsMap = map[string]string{
		"timestamp":       "rt",
		"id":              "eventId",
		"bytes_in":        "in",
		"bytes_out":       "out",
		"src":             "src",
		"src_port":        "spt",
		"uri_path":        "request",
		"dest":            "dst",
		"dest_port":       "dpt",
		"http_method":     "requestMethod",
		"http_referrer":   "requestContext",
		"url_domain":      "dhost",
		"user":            "suser",
		"cookie":          "requestCookies",
		"http_user_agent": "requestClientApplication",
		"action":          "act",
		"app":             "app",
		"process_id":      "spid",
		"process_path":    "filePath",
		"proctitle":       "sproc",
		"args":            "sproc",
		"exe":             "sproc",
		"process_name":    "sproc",
		"uid":             "suid",
	}
)
