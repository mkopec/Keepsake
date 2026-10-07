# tpm-fido

tpm-fido is FIDO token implementation for Linux that protects the token keys by using your system's TPM. tpm-fido uses Linux's [uhid](https://github.com/psanford/uhid) facility to emulate a USB HID device so that it is properly detected by browsers.

It speaks U2F and CTAP 2.0: passkeys, a PIN enforced by the TPM, `hmac-secret` (e.g. for LUKS) and `credProtect`. On GNOME it uses the system prompt for confirmations, refuses requests while the screen is locked, works with GNOME's SSH agent, and comes with a "Security Keys" app.

## Quick start

```
make install               # as the user who will use tpm-fido; no root needed
sudo make install-system   # once per machine, then log out and back in
make enable                # start tpm-fido now and with every graphical login
```

Then set the TPM's lockout authorization (`tpm2_changeauth -c lockout <password>`) and set a PIN, e.g. in the Security Keys app. See [Installing](docs/installing.md) for details.

## Documentation

* [Installing](docs/installing.md): installation, permissions, dependencies
* [Security](docs/security.md): what tpm-fido protects against and what it doesn't, bus encryption, boot state binding
* [Design](docs/design.md): key handles, the device key, supported CTAP commands, the signature counter
* [Passkeys and reset](docs/passkeys.md)
* [PIN and user verification](docs/pin.md): the PIN in the TPM, `credProtect`
* [hmac-secret](docs/hmac-secret.md): disk encryption and other derived secrets
* [Desktop integration](docs/desktop.md): dialogs, screen lock, requests without a dialog, systemd, the Security Keys app
* [SSH](docs/ssh.md): `ecdsa-sk` keys and GNOME's SSH agent
* [Several users and TPM objects](docs/multi-user.md)
* [Testing](docs/testing.md)

## Source layout

* `src/`: the tpm-fido daemon (Go, package `main`) and its packages
* `src/cmd/tpm-fido-askpass/`: the SSH askpass program
* `src/settings/`: the Security Keys app (Python, GTK 4 / libadwaita)
* `contrib/`: systemd unit and udev rule
* `scripts/`: test helpers
