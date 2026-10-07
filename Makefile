# keepsake
#
#   make                     build keepsake
#   make install             install for the current user (no root needed)
#   make enable              start keepsake now and with every graphical login
#   make enable-gnome-ssh    let GNOME's SSH agent ask for security key PINs
#   sudo make install-system udev rule, uhid module, add $SUDO_USER to tss
#
# The user install goes to ~/.local and ~/.config by default. Packagers can
# set PREFIX=/usr and DESTDIR.

PREFIX           ?= $(HOME)/.local
BINDIR           ?= $(PREFIX)/bin
DATADIR          ?= $(PREFIX)/share
# not $(DATADIR)/keepsake: that is keepsake's private data directory
APPDIR           ?= $(DATADIR)/keepsake-settings
SYSTEMD_USER_DIR ?= $(if $(filter $(HOME)/%,$(PREFIX)),$(HOME)/.config/systemd/user,$(PREFIX)/lib/systemd/user)
UDEV_RULES_DIR   ?= /etc/udev/rules.d
MODULES_LOAD_DIR ?= /etc/modules-load.d

GO     ?= go
GOFLAGS ?= -trimpath

DESKTOP_FILE = io.github.mkopec.Keepsake.desktop

.PHONY: all build test check install uninstall migrate-tpm-fido enable disable enable-gnome-ssh disable-gnome-ssh install-system uninstall-system check-deps help

GCR_SSH_DROPIN = $(HOME)/.config/systemd/user/gcr-ssh-agent.service.d/keepsake-askpass.conf

all: build

help:
	@sed -n '3,10p' Makefile | sed 's/^# \{0,1\}//'

GO_SOURCES = $(shell find . -name '*.go' -not -path './.git/*') go.mod go.sum

build: keepsake keepsake-askpass

keepsake: $(GO_SOURCES)
	$(GO) build $(GOFLAGS) -o $@ ./src

keepsake-askpass: $(GO_SOURCES)
	$(GO) build $(GOFLAGS) -o $@ ./src/cmd/keepsake-askpass

test:
	$(GO) test ./...

# also runs the TPM tests against swtpm, see docs/testing.md
check:
	$(GO) vet ./...
	@test -n "$(KEEPSAKE_SWTPM)" || { echo "set KEEPSAKE_SWTPM to an swtpm socket to run the TPM tests"; exit 1; }
	KEEPSAKE_SWTPM=$(KEEPSAKE_SWTPM) $(GO) test -count=1 ./...

# Removes an install from the time Keepsake was called tpm-fido: two
# daemons would compete for the same TPM objects. Credentials are kept.
OLD_GCR_SSH_DROPIN = $(HOME)/.config/systemd/user/gcr-ssh-agent.service.d/tpm-fido-askpass.conf

migrate-tpm-fido:
	@if [ -z "$(DESTDIR)" ] && [ -e $(HOME)/.config/systemd/user/tpm-fido.service ]; then \
		echo "Replacing the previous tpm-fido install"; \
		systemctl --user disable --now tpm-fido.service 2>/dev/null || true; \
		rm -f $(HOME)/.config/systemd/user/tpm-fido.service; \
	fi
	@if [ -z "$(DESTDIR)" ]; then \
		rm -f $(BINDIR)/tpm-fido $(BINDIR)/tpm-fido-askpass $(BINDIR)/tpm-fido-settings; \
		rm -rf $(DATADIR)/tpm-fido-settings; \
		rm -f $(DATADIR)/applications/io.github.psanford.TpmFido.Settings.desktop; \
		if [ -f $(OLD_GCR_SSH_DROPIN) ]; then \
			rm -f $(OLD_GCR_SSH_DROPIN); \
			echo "Run 'make enable-gnome-ssh' again to use keepsake-askpass with GNOME's SSH agent."; \
		fi; \
	fi

install: build migrate-tpm-fido
	@if [ "$$(id -u)" = 0 ] && [ -z "$(DESTDIR)" ] && [ "$(PREFIX)" = "$(HOME)/.local" ]; then \
		echo "Run 'make install' as the user who will use keepsake; use 'sudo make install-system' for the system parts."; \
		exit 1; \
	fi
	install -Dm755 keepsake $(DESTDIR)$(BINDIR)/keepsake
	install -Dm755 keepsake-askpass $(DESTDIR)$(BINDIR)/keepsake-askpass
	install -Dm755 src/settings/keepsake-settings $(DESTDIR)$(APPDIR)/keepsake-settings
	install -Dm644 src/settings/securitykeys.py $(DESTDIR)$(APPDIR)/securitykeys.py
	ln -sfn $(APPDIR)/keepsake-settings $(DESTDIR)$(BINDIR)/keepsake-settings
	install -d $(DESTDIR)$(DATADIR)/applications $(DESTDIR)$(SYSTEMD_USER_DIR)
	sed 's|^Exec=.*|Exec=$(BINDIR)/keepsake-settings|' src/settings/$(DESKTOP_FILE) \
		> $(DESTDIR)$(DATADIR)/applications/$(DESKTOP_FILE)
	sed 's|^ExecStart=.*|ExecStart=$(BINDIR)/keepsake|' contrib/systemd/keepsake.service \
		> $(DESTDIR)$(SYSTEMD_USER_DIR)/keepsake.service
	@if [ -z "$(DESTDIR)" ]; then \
		systemctl --user daemon-reload 2>/dev/null || true; \
		update-desktop-database $(DATADIR)/applications 2>/dev/null || true; \
		echo; \
		echo "Installed. Next steps:"; \
		echo "  sudo make install-system   # once per machine, then log in again"; \
		echo "  make enable                # start keepsake with your graphical session"; \
		$(MAKE) --no-print-directory check-deps; \
	fi

uninstall: disable disable-gnome-ssh
	rm -f $(DESTDIR)$(BINDIR)/keepsake $(DESTDIR)$(BINDIR)/keepsake-askpass $(DESTDIR)$(BINDIR)/keepsake-settings
	rm -f $(DESTDIR)$(APPDIR)/keepsake-settings $(DESTDIR)$(APPDIR)/securitykeys.py
	rm -rf $(DESTDIR)$(APPDIR)/__pycache__
	-rmdir $(DESTDIR)$(APPDIR) 2>/dev/null
	rm -f $(DESTDIR)$(DATADIR)/applications/$(DESKTOP_FILE)
	rm -f $(DESTDIR)$(SYSTEMD_USER_DIR)/keepsake.service
	@echo "Your credentials (~/.local/share/keepsake and the TPM objects) were kept."

enable:
	systemctl --user daemon-reload
	systemctl --user enable --now keepsake.service
	@echo "Logs: journalctl --user -u keepsake -f"

disable:
	@if [ -z "$(DESTDIR)" ] && systemctl --user cat keepsake.service >/dev/null 2>&1; then \
		systemctl --user disable --now keepsake.service; \
	fi

# GNOME's SSH agent (gcr-ssh-agent) runs an ssh-agent that asks for the PIN
# of verify-required security keys (ssh-keygen -O verify-required) through
# SSH_ASKPASS. Without one it refuses to sign ("agent refused operation").
# Restarting it forgets keys added with ssh-add; keys in ~/.ssh are loaded
# again automatically.
enable-gnome-ssh:
	@test -x $(BINDIR)/keepsake-askpass || { echo "run 'make install' first"; exit 1; }
	install -d $(dir $(GCR_SSH_DROPIN))
	printf '[Service]\nEnvironment=SSH_ASKPASS=%s\nEnvironment=SSH_ASKPASS_REQUIRE=force\n' \
		'$(BINDIR)/keepsake-askpass' > $(GCR_SSH_DROPIN)
	systemctl --user daemon-reload
	systemctl --user try-restart gcr-ssh-agent.service
	@echo "gcr-ssh-agent now asks for security key PINs with keepsake-askpass."

disable-gnome-ssh:
	@if [ -z "$(DESTDIR)" ] && [ -f $(GCR_SSH_DROPIN) ]; then \
		rm -f $(GCR_SSH_DROPIN); \
		rmdir $(dir $(GCR_SSH_DROPIN)) 2>/dev/null; \
		systemctl --user daemon-reload; \
		systemctl --user try-restart gcr-ssh-agent.service; \
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
			echo "Add the users of keepsake to the group owning /dev/tpmrm0 (usually tss)."; \
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
