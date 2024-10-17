.PHONY: codegen

codegen:
	go install github.com/atombender/go-jsonschema@v0.16.0
	for schema in json_schemas/*; do \
		schema_name=$$(basename "$${schema%.*}"); \
		go-jsonschema -p types "$$schema" -e -o types/$${schema_name}.go; \
	done

	go generate ./...
	go fmt ./...
