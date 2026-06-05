BINARY := debian-routerd
PREFIX ?= /usr/local
SYSCONFDIR ?= /etc/debian-router
DATADIR ?= /usr/share/debian-router

.PHONY: build test run plan validate install-local

build:
	go build -o $(BINARY) ./cmd/debian-routerd

test:
	go test ./...

run:
	go run ./cmd/debian-routerd --config ./configs/router.example.json --web-dir ./web

plan:
	go run ./cmd/debian-routerd --config ./configs/router.example.json --plan

validate:
	go run ./cmd/debian-routerd --config ./configs/router.example.json --validate

install-local: build
	install -d $(DESTDIR)$(PREFIX)/sbin
	install -d $(DESTDIR)$(DATADIR)/web
	install -d $(DESTDIR)$(SYSCONFDIR)
	install -m 0755 $(BINARY) $(DESTDIR)$(PREFIX)/sbin/$(BINARY)
	cp -R web/. $(DESTDIR)$(DATADIR)/web/
	if [ ! -f $(DESTDIR)$(SYSCONFDIR)/router.json ]; then install -m 0600 configs/router.example.json $(DESTDIR)$(SYSCONFDIR)/router.json; fi

