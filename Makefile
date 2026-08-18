BINARY:=bin/glvd2

default: build

setup:
	mkdir -p data
	mise install

.PHONY: build
build:
	@go build -o $(BINARY) ./cmd/glvd2/

.PHONY: fmt
fmt: format

.PHONY: format
format: format-toml
	@echo "Formatting go files..."
	golangci-lint fmt

.PHONY: format-toml
format-toml:
	@echo "Formatting TOML files..."
	mise run fmt:toml

.PHONY: lint
lint:
	golangci-lint --config=.golangci.yaml run

.PHONY: test
test: clean_test
	gotestsum

.PHONY: test-coverage-html
test-coverage-html: clean_test
	go test --covermode=atomic --coverprofile=coverage.out -v ./...
	go tool cover -html=coverage.out

.PHONY: db_code_generate
db_code_generate:
	sqlc generate

.PHONY: db_migrate_create
db_migrate_create:
	@read -p "Enter name for the migration: " mig_name; \
	migrate create -ext=sql -dir=internal/db/migrations -seq $$mig_name

.PHONY: db_migrate_up
db_migrate_up:
	migrate -path=internal/db/migrations -database "sqlite://data/internal.sqlite?x-no-tx-wrap=true" -verbose up

.PHONY: db_migrate_down
db_migrate_down:
	migrate -path=internal/db/migrations -database "sqlite://data/internal.sqlite?x-no-tx-wrap=true" -verbose down

.PHONY: regenerate
regenerate:
	bin/glvd2 regenerate

.PHONY: clean_test
clean_test:
	go clean -testcache

.PHONY: clean
clean: clean_test
	$(RM) $(BINARY)

sbom:
	syft dir:. -c config/syft.yaml -o cyclonedx-json=bin/sbom.cyclonedx.json
