.PHONY: build check fmt test install-hooks

build:
	go build ./...

fmt:
	gofmt -w .

check:
	@test -z "$$(gofmt -l .)" || (echo "gofmt needed on:" && gofmt -l . && exit 1)
	go vet ./...
	go test -race ./... -count=1

test:
	go test ./...

install-hooks:
	cp hooks/pre-commit .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit
