# tpm-fido

tpm-fido is FIDO token implementation for Linux that protects the token keys by using your system's TPM. tpm-fido uses Linux's [uhid](https://github.com/psanford/uhid) facility to emulate a USB HID device so that it is properly detected by browsers.

##  Implementation details

tpm-fido uses the TPM 2.0 API. The overall design is as follows:

On registration tpm-fido generates a new P256 primary key under the Owner hierarchy on the TPM. To ensure that the key is unique per site and registration, tpm-fido generates a random 20 byte seed for each registration. The primary key template is populated with unique values from a sha256 hkdf of the 20 byte random seed and the application parameter provided by the browser.

A signing child key is then generated from that primary key. The key handle returned to the caller is a concatenation of the child key's public and private key handles and the 20 byte seed.

On an authentication request, tpm-fido will attempt to load the primary key by initializing the hkdf in the same manner as above. It will then attempt to load the child key from the provided key handle. Any incorrect values or values created by a different TPM will fail to load.

### Device key

Current versions add a device key: a keyed hash key with a TPM generated secret, made persistent in your slot (see [TPM objects](#tpm-objects)), with an authorization value derived from your user secret, whose wrapped private area is discarded. Instead of the random seed itself, the primary key template uses an HMAC, computed with the device key, of the seed and a version byte. The version byte records whether the credential was created with `hmac-secret`, whether it is a passkey and its `credProtect` level. Because the version byte is part of the HMAC, a credential ID whose flags were modified doesn't load. (Development versions before this used a format that didn't authenticate the flags, which let a deleted passkey be used again by clearing its "passkey" flag; their credential IDs are no longer accepted.)

Because the device key can't be loaded again once it is evicted from the TPM, replacing it (`authenticatorReset`) irrecoverably invalidates every credential created with it. Key handles from versions without a device key ("legacy" key handles) keep working until the first reset; the reset sets a flag in your slot's state index that disables them for you.

Software running as you can read the user secret and so use the device key; other users can't (see [Several users](#several-users)).

New key handles also set `noDA` on their keys. The keys have an empty authorization value, so dictionary attack protection doesn't protect anything, and without `noDA` the TPM refuses to use them while it is in lockout. Legacy key handles can't be used during a lockout.

### FIDO2 (CTAP2)

tpm-fido speaks both U2F (CTAP1) and CTAP 2.0. The CTAP2 `rpIdHash` is the same value as the U2F application parameter, so CTAP2 credential IDs use the key handle format described above, and credentials registered over U2F keep working over CTAP2.

Supported: `authenticatorMakeCredential` (ES256 only, "packed" self attestation), `authenticatorGetAssertion` and `authenticatorGetNextAssertion` (including discoverable credentials, i.e. passkeys), `authenticatorGetInfo`, `authenticatorClientPIN` (PIN protocols 1 and 2), `authenticatorReset`, the credential management preview command of `FIDO_2_1_PRE` authenticators, and the `hmac-secret` and `credProtect` extensions.

User presence is confirmed in a dialog showing the relying party ID and user name (see [Desktop integration](#desktop-integration)).

### Passkeys

Discoverable credentials (passkeys) are credentials like any other, flagged as discoverable. Their metadata (relying party, user ID, user name and display name, public key) is stored in `$XDG_DATA_HOME/tpm-fido/passkeys` (`~/.local/share/tpm-fido/passkeys`, change it with `-passkey-store`). The file is encrypted with AES-256-GCM using a key derived from the device key, so it can only be read with this TPM.

A passkey can only be used while it is in the store, so deleting a passkey revokes it, even for a site that still knows its credential ID. Registering a new passkey for the same site and user replaces (and revokes) the old one. Up to 128 passkeys can be stored. If the store can't be decrypted (because the TPM was cleared, for example), it is moved aside to `passkeys.undecryptable-<time>` and a new one is started.

When a site asks for a passkey without user verification, only the user ID is returned; user names are only returned after the PIN was verified (CTAP 2.0).

Passkeys can be listed and deleted with tools that support credential management, for example `fido2-token -L -r`, `fido2-token -L -k <rp id>` and `fido2-token -D -i <credential id>`, or Chrome's security key settings. These require the PIN.

### Reset

`authenticatorReset` (for example `fido2-token -R`, or "Reset your security key" in Chrome) replaces the device key, disables legacy key handles, removes the PIN and deletes the passkey store. Every credential stops working, including hmac-secret secrets, so LUKS keys enrolled with tpm-fido are lost. Hardware authenticators only accept a reset shortly after being plugged in; tpm-fido instead asks for confirmation in the `pinentry` dialog.

### PIN

The PIN is set, entered and changed by the platform (browser, `fido2-token -S`, ...), as with a hardware security key. Once a PIN is set, every registration requires it (CTAP 2.0); sign-ins require it when the site asks for user verification.

The PIN is stored in the TPM in your slot's PIN index (see [TPM objects](#tpm-objects)):

* The index's authorization value is derived from `LEFT(SHA-256(PIN), 16)`, the PIN hash defined by CTAP, and your user secret. tpm-fido checks a PIN by reading the index with that authorization value. The PIN hash is never stored on disk.
* The index's single byte of data is the remaining PIN retries. It is decremented before each check and reset after a correct PIN. After 8 wrong PINs the PIN is blocked; after 3 in a row tpm-fido must be restarted (the equivalent of unplugging a security key).
* The index doesn't have `noDA` set, so every wrong PIN also counts towards the TPM's dictionary attack lockout. This limits guessing even for software that talks to the TPM directly instead of going through tpm-fido. While the TPM is in lockout, PIN checks fail with `PIN_AUTH_BLOCKED` without using up a retry. Note that the lockout is TPM-wide: wrong FIDO PINs also count towards the lockout of other DA-protected objects (for example a TPM+PIN LUKS key), and vice versa. `tpm2_getcap properties-variable` shows the TPM's `MAX_AUTH_FAIL` and `LOCKOUT_INTERVAL`.
* The lockout only limits guessing if the TPM's lockout authorization is set (`tpm2_changeauth -c lockout`). With an empty lockout authorization, anyone who can use the TPM can reset the lockout counter (`tpm2_dictionarylockout -c`) and guess without limit. The retries counter doesn't help either: it can be rewritten with the (empty) owner authorization.
  tpm-fido warns at startup when the lockout authorization isn't set.

Limitations:

* The PIN only gates what tpm-fido does, except for credentials created with `credProtect` level 3 (see below). The keys of other credentials aren't bound to the PIN, so software running as your user can still use them through the TPM directly.
* A blocked or forgotten PIN is removed by resetting the authenticator. Deleting only the PIN index (`tpm2_nvundefine -C o <PIN index>`) also removes the PIN and keeps the existing credentials, but it destroys the UV key, so every hmac-secret secret that was derived with user verification (for example a LUKS key enrolled with `--fido2-with-client-pin=yes`) is lost.

### credProtect: credentials bound to the PIN

A relying party can create a credential with the `credProtect` extension. Level 2 (`userVerificationOptionalWithCredentialIDList`) passkeys are only discovered after the PIN was entered. Level 3 (`userVerificationRequired`) credentials can only be used with the PIN, and tpm-fido enforces this in the TPM: the credential key has no usable authorization value, only a policy (`TPM2_PolicySecret`) that requires the UV key, whose authorization value is the PIN hash. So even software that talks to the TPM directly can't sign with it without the PIN, and every wrong guess counts towards the TPM's dictionary attack lockout.

* Level 3 needs a PIN to be set when the credential is created.
* The binding survives PIN changes (the UV key is re-wrapped, not replaced), but not removing the PIN index: a new PIN creates a new UV key.
* Level 3 credential IDs are 279 bytes, too long for U2F.
* Without the PIN, level 3 credentials are invisible: they aren't returned, and aren't recognized in an allowList or excludeList.

Request it with `fido2-cred -M -c 3`, the `credentialProtectionPolicy: "userVerificationRequired"` WebAuthn extension, or (depending on the OpenSSH version) `ssh-keygen -t ecdsa-sk -O verify-required`.

### Bus encryption

Commands that carry secrets (PIN hashes, hmac-secret outputs, the passkey store key) use HMAC sessions salted with the TPM's storage root key, with parameter encryption, so someone recording the bus of a discrete TPM sees neither the PIN hash nor anything to brute force it from, nor the hmac-secret outputs. To protect against an active interposer, the storage root key's name is pinned on first use in `srk-name` next to the passkey store; if it changes, tpm-fido refuses to start. (It also changes when the TPM is cleared, which destroys all tpm-fido credentials anyway; delete the file then.) Signatures and credential IDs aren't secret and aren't encrypted.

### hmac-secret

Credentials created with the `hmac-secret` extension can derive secrets from salts, which is what `systemd-cryptenroll --fido2-device`, `age-plugin-fido2-hmac` and similar tools use. Each credential has two secrets (`CredRandomWithoutUV` and `CredRandomWithUV` in CTAP 2.1). tpm-fido derives them by HMACing the relying party and credential ID with one of two TPM keys:

* Without user verification: the device key. It never leaves the TPM and is destroyed by a reset or when the TPM is cleared. Using it needs your user secret, so other users of the TPM can't compute these secrets, but **anyone who can read your files and use the TPM can**: software running as you, or someone who boots another OS on the machine while your home directory isn't encrypted. The credential ID is not secret (systemd stores it in the LUKS header).
* With user verification (a PIN): an ordinary keyed hash key whose authorization value is the PIN hash. It is stored, wrapped by the TPM, in the PIN index. Computing these secrets requires the PIN, even with direct access to the TPM, and guessing it counts towards the TPM's dictionary attack lockout. Changing the PIN re-wraps the same key (`TPM2_ObjectChangeAuth`), so the secrets survive PIN changes.

For disk encryption, enroll with a PIN:

```
systemd-cryptenroll --fido2-device=auto --fido2-with-client-pin=yes /dev/sdXn
```

Both secrets are lost when the authenticator is reset or the TPM is cleared or replaced, so keep another way to unlock (a recovery key or passphrase).

tpm-fido keeps the PIN hash in memory while the PIN token it was issued for is valid (until the next `getPinToken`, PIN change or restart), because the UV key needs it at assertion time.

### Signature counter

The signature counter is a TPM NV counter in your slot. tpm-fido defines the index on first start, which requires the owner hierarchy to have an empty authorization value. The index is an orderly (hybrid) counter, so the TPM doesn't write NV on every signature. After an unclean shutdown the counter jumps forward.

Older versions of tpm-fido reported the number of seconds since 2021-01-01 as the counter. The NV counter value is offset by `0x10000000` so it stays above any of those values.

## Status

tpm-fido has been tested to work with Chrome and Firefox on Linux.

CTAP2 support has been tested with libfido2 (`fido2-cred`, `fido2-assert`, `fido2-token`) and python-fido2 against swtpm. To run against swtpm:

```
swtpm socket --tpm2 --tpmstate dir=/tmp/swtpm --server type=unixio,path=/tmp/swtpm/sock --flags not-need-init,startup-clear
./tpm-fido -device /tmp/swtpm/sock
```

## Desktop integration

### Confirmation dialogs

On GNOME, tpm-fido shows its dialogs with the GNOME Shell system prompter, the same system-modal dialog GNOME Keyring uses, over gcr's D-Bus interface (`org.gnome.keyring.SystemPrompter`). Elsewhere it falls back to `pinentry`. Choose explicitly with `-prompt gnome` (which also starts gcr's `gcr-prompter` on other desktops) or `-prompt pinentry`.

tpm-fido only accepts answers from the connection that owns the prompter's bus name, so other programs on the session bus can't confirm a prompt.

### Screen lock

While the session is locked or inactive (another user's session is in the foreground), tpm-fido refuses every request except `authenticatorGetInfo`: nobody can confirm them, and requests that don't need confirmation (`up=false` sign-ins, which can also return hmac-secret secrets) shouldn't succeed while you are away. A dialog that is open when the screen locks is closed and its request refused. U2F requests are answered like a key waiting for a touch, so the browser keeps waiting.

tpm-fido asks logind (`LockedHint` and `Active` of the user's session) and GNOME Shell's screen shield (`org.gnome.ScreenSaver`). If neither can be asked, requests are allowed. Disable the check with `-lock-check=false`.

### systemd user service

`make install` installs a user service that starts tpm-fido with the graphical session, restarts it if it fails, and stops it at logout. Enable it with `make enable`; logs are in `journalctl --user -u tpm-fido -f`.

Stopping the service (`systemctl --user stop tpm-fido`) removes the virtual security key, for example to use only a hardware key for a while. The credentials stay in the TPM.

### SSH keys and GNOME's SSH agent

`ssh-keygen -t ecdsa-sk` works with tpm-fido; with `-O verify-required` every signature also needs the PIN. ssh asks for the PIN in the terminal, but an SSH agent has no terminal and asks through `SSH_ASKPASS`; without one it refuses to sign ("agent refused operation"). GNOME's agent (`gcr-ssh-agent`, `SSH_AUTH_SOCK=/run/user/$UID/gcr/ssh`) has none configured.

`tpm-fido-askpass` is an askpass program for GNOME. To use it with GNOME's agent:

```
make install
make enable-gnome-ssh   # adds a drop-in to gcr-ssh-agent.service and restarts it
```

* **Security key PINs:** if tpm-fido runs, tpm-fido-askpass asks it for the PIN over D-Bus (`io.github.psanford.TpmFido`), and tpm-fido shows a single "Sign In with SSH Key?" prompt. Typing the PIN into a prompt tpm-fido showed proves that you are present, so the signature that follows doesn't show tpm-fido's confirmation dialog: one prompt instead of two. This presence grant is used once, expires after 15 seconds, and only applies to a request whose verified PIN is the one you typed. Other programs can ask tpm-fido to show the prompt (as they could show any prompt), but can't answer it. Without tpm-fido (e.g. for a hardware key), it asks with the GNOME system prompt; the PIN travels from the prompt encrypted with gcr's secret exchange. Disable the combined prompt with `tpm-fido -askpass-service=false`.
* **Key passphrases and `ssh-add -c` confirmations:** GNOME system prompt. gcr-ssh-agent's own passphrase prompts for keys in `~/.ssh` (with "remember in keyring") are unaffected: gcr runs `ssh-add` with its own askpass.
* **"Touch your security key":** a desktop notification, unless tpm-fido handles the request (it shows its own dialog).
* Without a GNOME system prompter it runs `$TPMFIDO_ASKPASS_FALLBACK` or OpenSSH's `ssh-askpass`.

`make disable-gnome-ssh` removes the drop-in. It also works with OpenSSH's own agent: set `SSH_ASKPASS` to `tpm-fido-askpass` and `SSH_ASKPASS_REQUIRE=force` in its environment.

### Security Keys app

`settings/tpm-fido-settings` is a GTK 4 / libadwaita app to set and change the PIN, list and delete passkeys, and reset the security key. It uses standard CTAP2 commands (python-fido2), so it also manages hardware security keys. It needs PyGObject, libadwaita and python-fido2 (on Arch: `python-gobject libadwaita python-fido2`). `make install` installs it; it shows up as "Security Keys". Listing and deleting passkeys requires the PIN.

## Installing

```
make install               # as the user who will use tpm-fido; no root needed
sudo make install-system   # once per machine, then log out and back in
make enable                # start tpm-fido now and with every graphical login
```

* `make install` builds tpm-fido and installs it, the Security Keys app and the systemd user service under `~/.local` and `~/.config`. `make check-deps` reports missing dependencies and permissions.
* `sudo make install-system` installs a udev rule that gives the user logged in at the local desktop access to `/dev/uhid` (so tpm-fido can appear as a USB security key), loads the `uhid` module at boot, and adds you (`$SUDO_USER`, or `TPM_USER=<name>`) to the `tss` group, which may use `/dev/tpmrm0`. Access to `/dev/uhid` allows creating any HID device, including keyboards; the rule limits it to the active local session. Without a local session (e.g. over SSH), use `GROUP="<a group you are in>", MODE="0660"` instead of `TAG+="uaccess"` in `/etc/udev/rules.d/70-uhid.rules`.
* Set the TPM's lockout authorization (`tpm2_changeauth -c lockout <password>`) so the TPM's dictionary attack protection actually limits PIN guessing.
* `make uninstall` and `sudo make uninstall-system` remove the files again. Credentials are kept: they are in the TPM and `~/.local/share/tpm-fido`.

Packagers can set `PREFIX=/usr` and `DESTDIR`. Run tpm-fido as the user, not as root.

### Several users

Every member of the `tss` group can use the TPM directly, and the owner hierarchy has an empty authorization value, so tpm-fido can't rely on the TPM's access control between users. Instead, each user has

* their own TPM objects, in a slot derived from their user ID (`-slot` chooses another; user IDs above 65535 must choose one), and
* a random user secret in `~/.local/share/tpm-fido/user-secret`. The device key's authorization value and the PIN's authorization values in the TPM are derived from it.

Every credential, the hmac-secret secrets and the passkey store depend on the device key, so another user of the TPM who can't read your user secret can't use your credentials, compute your hmac-secret secrets (e.g. LUKS keys), read your passkeys or even start guessing your PIN. tpm-fido refuses to start if the device key in its slot doesn't accept its user secret (another user's slot, or a replaced user secret file).

Other users can still delete your TPM objects, which destroys your credentials but doesn't give access to them. Credentials registered with upstream tpm-fido (legacy key handles) depend only on the credential ID and aren't protected; reset the security key to retire them.

**Don't lose `~/.local/share/tpm-fido`.** Without the user secret, none of your credentials can be used anymore. A backup only helps on the same TPM.

### TPM objects

tpm-fido creates these TPM objects, which requires the owner hierarchy to have an empty authorization value. For slot *s* (by default your user ID):

| Handle | Contents | Created |
|---|---|---|
| `0x01300000 + 4s` | signature counter | on first start |
| `0x01300000 + 4s + 1` | PIN and UV key | when a PIN is set |
| `0x01300000 + 4s + 2` | state flags | on the first reset |
| `0x81300000 + s` | device key (persistent) | on first start |

For user ID 1000: `0x01300FA0`–`0x01300FA2` and `0x813003E8`. Development versions used fixed handles (`0x0100F1D0`–`0x0100F1D2`, `0x8100F1D0`) for everyone; tpm-fido mentions them at startup if they are still there.

## Dependencies

Outside GNOME, tpm-fido requires `pinentry` to be available on the system. If you have gpg installed you most likely already have `pinentry`.
