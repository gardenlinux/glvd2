BINARY:=bin/glvd2

default: build

.PHONY: build
build:
	@go build -o $(BINARY) cmd/glvd2/main.go

.PHONY: format
format:
	gofmt -l -s -w .

.PHONY: lint
lint:
	golangci-lint run

.PHONY: test
test: clean_test
	go test -v ./...

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

.PHONY: clean_test
clean_test:
	go clean -testcache

.PHONY: clean
clean: clean_test
	$(RM) $(BINARY)