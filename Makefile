# Требуется GNU make; на Windows — из Git Bash/MSYS2 (нужен sh для fmt-check).

GO          ?= go
BINARY      := trossd
VERSION     ?= 0.0.0-dev
LDFLAGS     := -s -w -X main.version=$(VERSION)
EXE         := $(shell $(GO) env GOEXE)
STATICCHECK := honnef.co/go/tools/cmd/staticcheck@v0.8.1
LINT_TOOLCHAIN := go1.26.9
TOOLS       := $(CURDIR)/bin/tools

.PHONY: all build build-linux run test lint vet vet-linux staticcheck fmt fmt-check tidy clean lab-sync lab-test lab-itest

all: lint test build

build:
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/$(BINARY)$(EXE) ./cmd/trossd

# Статический бинарник для мини-ПК (Debian, amd64); cgo не нужен.
build-linux: export GOOS := linux
build-linux: export GOARCH := amd64
build-linux: export CGO_ENABLED := 0
build-linux:
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/linux-amd64/$(BINARY) ./cmd/trossd

# Запуск на машине разработчика: только «сухой» режим.
run: build
	./bin/$(BINARY)$(EXE) -config configs/example.yaml -dry-run

test:
	$(GO) test ./...

lint: fmt-check vet vet-linux staticcheck

vet:
	$(GO) vet ./...

# Проверка файлов под тегом linux при разработке на другой ОС.
vet-linux: export GOOS := linux
vet-linux: export GOARCH := amd64
vet-linux:
	$(GO) vet ./...

# staticcheck v0.8.1 не читает export data Go 1.27 — запускаем его под тулчейном 1.26
# (go.mod допускает 1.26; при первом запуске go сам скачает этот тулчейн).
staticcheck:
	GOTOOLCHAIN=$(LINT_TOOLCHAIN) GOBIN=$(TOOLS) $(GO) install $(STATICCHECK)
	GOTOOLCHAIN=$(LINT_TOOLCHAIN) $(TOOLS)/staticcheck$(EXE) ./...
	GOTOOLCHAIN=$(LINT_TOOLCHAIN) GOOS=linux GOARCH=amd64 $(TOOLS)/staticcheck$(EXE) ./...

fmt:
	gofmt -w .

fmt-check:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "not gofmt-ed:"; echo "$$out"; exit 1; fi

tidy:
	$(GO) mod tidy

# Стенд (адрес — в .lab.env): копирование кода, сборка и тесты на нём.
lab-sync:
	scripts/lab-sync build

lab-test:
	scripts/lab-sync test

lab-itest:
	scripts/lab-sync itest

clean:
	rm -rf bin
