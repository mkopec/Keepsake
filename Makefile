# tpm-fido
#
#   make                     build tpm-fido
#   make install             install for the current user (no root needed)
#   make enable              start tpm-fido now and with every graphical login
#   sudo make install-system udev rule, uhid module, add $SUDO_USER to tss
#
# The user install goes to ~/.local and ~/.config by default. Packagers can
# set PREFIX=/usr and DESTDIR.

PREFIX           ?= $(HOME)/.local
BINDIR           ?= $(PREFIX)/bin
DATADIR          ?= $(PREFIX)/share
# not $(DATADIR)/tpm-fido: that is tpm-fido's private data directory
APPDIR           ?= $(DATADIR)/tpm-fido-settings
SYSTEMD_USER_DIR ?= $(if $(filter $(HOME)/%,$(PREFIX)),$(HOME)/.config/systemd/user,$(PREFIX)/lib/systemd/user)
UDEV_RULES_DIR   ?= /etc/udev/rules.d
MODULES_LOAD_DIR ?= /etc/modules-load.d

GO     ?= go
GOFLAGS ?= -trimpath

DESKTOP_FILE = io.github.psanford.TpmFido.Settings.desktop

.PHONY: all build test check install uninstall enable disable install-system uninstall-system check-deps help

all: build

help:
	@sed -n '3,9p' Makefile | sed 's/^# \{0,1\}//'

build: tpm-fido

tpm-fido: $(shell find . -name '*.go' -not -path './.git/*') go.mod go.sum
	$(GO) build $(GOFLAGS) -o $@ .

test:
	$(GO) test ./...

# also runs the TPM tests against swtpm, see README
check:
	$(GO) vet ./...
	@test -n "$(TPMFIDO_SWTPM)" || { echo "set TPMFIDO_SWTPM to an swtpm socket to run the TPM tests"; exit 1; }
	TPMFIDO_SWTPM=$(TPMFIDO_SWTPM) $(GO) test -count=1 ./...

install: build
	@if [ "$$(id -u)" = 0 ] && [ -z "$(DESTDIR)" ] && [ "$(PREFIX)" = "$(HOME)/.local" ]; then \
		echo "Run 'make install' as the user who will use tpm-fido; use 'sudo make install-system' for the system parts."; \
		exit 1; \
	fi
	install -Dm755 tpm-fido $(DESTDIR)$(BINDIR)/tpm-fido
	install -Dm755 settings/tpm-fido-settings $(DESTDIR)$(APPDIR)/tpm-fido-settings
	install -Dm644 settings/securitykeys.py $(DESTDIR)$(APPDIR)/securitykeys.py
	ln -sfn $(APPDIR)/tpm-fido-settings $(DESTDIR)$(BINDIR)/tpm-fido-settings
	install -d $(DESTDIR)$(DATADIR)/applications $(DESTDIR)$(SYSTEMD_USER_DIR)
	sed 's|^Exec=.*|Exec=$(BINDIR)/tpm-fido-settings|' settings/$(DESKTOP_FILE) \
		> $(DESTDIR)$(DATADIR)/applications/$(DESKTOP_FILE)
	sed 's|^ExecStart=.*|ExecStart=$(BINDIR)/tpm-fido|' contrib/systemd/tpm-fido.service \
		> $(DESTDIR)$(SYSTEMD_USER_DIR)/tpm-fido.service
	@if [ -z "$(DESTDIR)" ]; then \
		systemctl --user daemon-reload 2>/dev/null || true; \
		update-desktop-database $(DATADIR)/applications 2>/dev/null || true; \
		echo; \
		echo "Installed. Next steps:"; \
		echo "  sudo make install-system   # once per machine, then log in again"; \
		echo "  make enable                # start tpm-fido with your graphical session"; \
		$(MAKE) --no-print-directory check-deps; \
	fi

uninstall: disable
	rm -f $(DESTDIR)$(BINDIR)/tpm-fido $(DESTDIR)$(BINDIR)/tpm-fido-settings
	rm -f $(DESTDIR)$(APPDIR)/tpm-fido-settings $(DESTDIR)$(APPDIR)/securitykeys.py
	rm -rf $(DESTDIR)$(APPDIR)/__pycache__
	-rmdir $(DESTDIR)$(APPDIR) 2>/dev/null
	rm -f $(DESTDIR)$(DATADIR)/applications/$(DESKTOP_FILE)
	rm -f $(DESTDIR)$(SYSTEMD_USER_DIR)/tpm-fido.service
	@echo "Your credentials (~/.local/share/tpm-fido and the TPM objects) were kept."

enable:
	systemctl --user daemon-reload
	systemctl --user enable --now tpm-fido.service
	@echo "Logs: journalctl --user -u tpm-fido -f"

disable:
	@if [ -z "$(DESTDIR)" ] && systemctl --user cat tpm-fido.service >/dev/null 2>&1; then \
		systemctl --user disable --now tpm-fido.service; \
	fi

# Run with sudo. Adds the user who ran sudo to the tss group, unless
# TPM_USER is set.
TPM_USER ?= $(SUDO_USER)

install-system:
	@if [ "$$(id -u)" != 0 ] && [ -z "$(DESTDIR)" ]; then echo "Run 'sudo make install-system'."; exit 1; fi
	install -Dm644 contrib/udev/70-uhid.rules $(DESTDIR)$(UDEV_RULES_DIR)/70-uhid.rules
	install -d $(DESTDIR)$(MODULES_LOAD_DIR)
	echo uhid > $(DESTDIR)$(MODULES_LOAD_DIR)/uhid.conf
	@if [ -z "$(DESTDIR)" ]; then \
		modprobe uhid; \
		udevadm control --reload; \
		udevadm trigger --name-match=uhid; \
		if [ -n "$(TPM_USER)" ] && getent group tss >/dev/null; then \
			usermod -aG tss "$(TPM_USER)" && echo "Added $(TPM_USER) to tss; log out and back in."; \
		else \
			echo "Add the users of tpm-fido to the group owning /dev/tpmrm0 (usually tss)."; \
		fi; \
		echo; \
		echo "Recommended: set the TPM's lockout authorization, so the PIN can't be brute forced:"; \
		echo "  tpm2_changeauth -c lockout <password>   (keep the password safe)"; \
	fi

uninstall-system:
	@if [ "$$(id -u)" != 0 ] && [ -z "$(DESTDIR)" ]; then echo "Run 'sudo make uninstall-system'."; exit 1; fi
	rm -f $(DESTDIR)$(UDEV_RULES_DIR)/70-uhid.rules $(DESTDIR)$(MODULES_LOAD_DIR)/uhid.conf
	@if [ -z "$(DESTDIR)" ]; then udevadm control --reload; fi
	@echo "Group memberships were kept."

# reports missing runtime dependencies
check-deps:
	@ok=1; \
	if ! command -v pinentry-gnome3 >/dev/null && ! command -v pinentry-qt >/dev/null && ! command -v pinentry >/dev/null \
		&& ! busctl --user status org.gnome.keyring.SystemPrompter >/dev/null 2>&1 && ! [ -x /usr/lib/gcr-prompter ]; then \
		echo "missing: a dialog program (GNOME, gcr or pinentry)"; ok=0; fi; \
	if ! python3 -c 'import gi; gi.require_version("Adw", "1")' 2>/dev/null; then \
		echo "missing (Security Keys app): PyGObject and libadwaita"; ok=0; fi; \
	if ! python3 -c 'import fido2' 2>/dev/null; then \
		echo "missing (Security Keys app): python-fido2"; ok=0; fi; \
	if [ ! -w /dev/uhid ]; then echo "no access to /dev/uhid yet: run 'sudo make install-system'"; ok=0; fi; \
	if [ ! -r /dev/tpmrm0 ] || [ ! -w /dev/tpmrm0 ]; then \
		echo "no access to /dev/tpmrm0 yet: run 'sudo make install-system' and log in again"; ok=0; fi; \
	if [ $$ok = 1 ]; then echo "all dependencies and permissions OK"; fi
