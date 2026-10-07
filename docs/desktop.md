# Desktop integration

## Confirmation dialogs

On GNOME, tpm-fido shows its dialogs with the GNOME Shell system prompter, the same system-modal dialog GNOME Keyring uses, over gcr's D-Bus interface (`org.gnome.keyring.SystemPrompter`). Elsewhere it falls back to `pinentry`. Choose explicitly with `-prompt gnome` (which also starts gcr's `gcr-prompter` on other desktops) or `-prompt pinentry`.

tpm-fido only accepts answers from the connection that owns the prompter's bus name, so other programs on the session bus can't confirm a prompt.

## Screen lock

While the session is locked or inactive (another user's session is in the foreground), tpm-fido refuses every request except `authenticatorGetInfo`: nobody can confirm them, and requests that don't need confirmation (`up=false` sign-ins, which can also return hmac-secret secrets) shouldn't succeed while you are away. A dialog that is open when the screen locks is closed and its request refused. U2F requests are answered like a key waiting for a touch, so the browser keeps waiting.

tpm-fido asks logind (`LockedHint` and `Active` of the user's session) and GNOME Shell's screen shield (`org.gnome.ScreenSaver`). If neither could ever be asked (no logind, no GNOME), requests are allowed; if they could be asked before and stop answering, requests are refused. Disable the check with `-lock-check=false`.

## Requests without a dialog

Physical security keys can sign without a touch when asked to (`up=false`), because unplugging them stops all use. tpm-fido is never unplugged, so by default:

* sign-ins without user presence still return a signature, with the "user present" flag clear (relying parties following WebAuthn, and sshd unless the key was created with `no-touch-required`, reject it), but **no hmac-secret output**;
* U2F signatures without user presence are refused.

Tools that derive keys without a touch need `-allow-silent`, e.g. LUKS enrolled with `systemd-cryptenroll --fido2-with-user-presence=no`. Anyone who can open the security key device and knows the credential ID (it is in the LUKS header) can then get the secret while tpm-fido runs.

tpm-fido shows at most 6 dialogs within 30 seconds (`-dialog-limit`), so a program can't flood the screen with them; further requests are refused without a dialog. Setting the first PIN also asks for confirmation, so a program can't set a PIN you don't know.

## systemd user service

`make install` installs a user service that starts tpm-fido with the graphical session, restarts it if it fails, and stops it at logout. Enable it with `make enable`; logs are in `journalctl --user -u tpm-fido -f`.

Stopping the service (`systemctl --user stop tpm-fido`) removes the virtual security key, for example to use only a hardware key for a while. The credentials stay in the TPM.

## Security Keys app

`src/settings/tpm-fido-settings` is a GTK 4 / libadwaita app to set and change the PIN, list and delete passkeys, and reset the security key. It uses standard CTAP2 commands (python-fido2), so it also manages hardware security keys. It needs PyGObject, libadwaita and python-fido2 (on Arch: `python-gobject libadwaita python-fido2`). `make install` installs it; it shows up as "Security Keys". Listing and deleting passkeys requires the PIN.
