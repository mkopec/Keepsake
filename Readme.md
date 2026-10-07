# tpm-fido

tpm-fido is FIDO token implementation for Linux that protects the token keys by using your system's TPM. tpm-fido uses Linux's [uhid](https://github.com/psanford/uhid) facility to emulate a USB HID device so that it is properly detected by browsers.

##  Implementation details

tpm-fido uses the TPM 2.0 API. The overall design is as follows:

On registration tpm-fido generates a new P256 primary key under the Owner hierarchy on the TPM. To ensure that the key is unique per site and registration, tpm-fido generates a random 20 byte seed for each registration. The primary key template is populated with unique values from a sha256 hkdf of the 20 byte random seed and the application parameter provided by the browser.

A signing child key is then generated from that primary key. The key handle returned to the caller is a concatenation of the child key's public and private key handles and the 20 byte seed.

On an authentication request, tpm-fido will attempt to load the primary key by initializing the hkdf in the same manner as above. It will then attempt to load the child key from the provided key handle. Any incorrect values or values created by a different TPM will fail to load.

### Device key

Current versions add a device key: a keyed hash key with a TPM generated secret, made persistent at handle `0x8100F1D0` (change it with `-device-key-handle`), whose wrapped private area is discarded. Instead of the random seed itself, the primary key template uses an HMAC of the seed computed with the device key. The credential's seed byte also records whether the credential was created with `hmac-secret` and whether it is a passkey.

Because the device key can't be loaded again once it is evicted from the TPM, replacing it (`authenticatorReset`) irrecoverably invalidates every credential created with it. Key handles from versions without a device key ("legacy" key handles) keep working until the first reset; the reset sets a flag in NV index `0x0100F1D2` (`-state-index`) that disables them.

The device key, like the credential keys, has an empty authorization value: software that can use the TPM can use it.

New key handles also set `noDA` on their keys. The keys have an empty authorization value, so dictionary attack protection doesn't protect anything, and without `noDA` the TPM refuses to use them while it is in lockout. Legacy key handles can't be used during a lockout.

### FIDO2 (CTAP2)

tpm-fido speaks both U2F (CTAP1) and CTAP 2.0. The CTAP2 `rpIdHash` is the same value as the U2F application parameter, so CTAP2 credential IDs use the key handle format described above, and credentials registered over U2F keep working over CTAP2.

Supported: `authenticatorMakeCredential` (ES256 only, "packed" self attestation), `authenticatorGetAssertion` and `authenticatorGetNextAssertion` (including discoverable credentials, i.e. passkeys), `authenticatorGetInfo`, `authenticatorClientPIN` (PIN protocols 1 and 2), `authenticatorReset`, the credential management preview command of `FIDO_2_1_PRE` authenticators, and the `hmac-secret` extension.

User presence is confirmed through `pinentry`, with the relying party ID and user name shown in the prompt.

### Passkeys

Discoverable credentials (passkeys) are credentials like any other, flagged as discoverable. Their metadata (relying party, user ID, user name and display name, public key) is stored in `$XDG_DATA_HOME/tpm-fido/passkeys` (`~/.local/share/tpm-fido/passkeys`, change it with `-passkey-store`). The file is encrypted with AES-256-GCM using a key derived from the device key, so it can only be read with this TPM.

A passkey can only be used while it is in the store, so deleting a passkey revokes it, even for a site that still knows its credential ID. Registering a new passkey for the same site and user replaces (and revokes) the old one. Up to 128 passkeys can be stored. If the store can't be decrypted (because the TPM was cleared, for example), it is moved aside to `passkeys.undecryptable-<time>` and a new one is started.

When a site asks for a passkey without user verification, only the user ID is returned; user names are only returned after the PIN was verified (CTAP 2.0).

Passkeys can be listed and deleted with tools that support credential management, for example `fido2-token -L -r`, `fido2-token -L -k <rp id>` and `fido2-token -D -i <credential id>`, or Chrome's security key settings. These require the PIN.

### Reset

`authenticatorReset` (for example `fido2-token -R`, or "Reset your security key" in Chrome) replaces the device key, disables legacy key handles, removes the PIN and deletes the passkey store. Every credential stops working, including hmac-secret secrets, so LUKS keys enrolled with tpm-fido are lost. Hardware authenticators only accept a reset shortly after being plugged in; tpm-fido instead asks for confirmation in the `pinentry` dialog.

### PIN

The PIN is set, entered and changed by the platform (browser, `fido2-token -S`, ...), as with a hardware security key. Once a PIN is set, every registration requires it (CTAP 2.0); sign-ins require it when the site asks for user verification.

The PIN is stored in the TPM in NV index `0x0100F1D1` (change it with `-pin-index`):

* The index's authorization value is `LEFT(SHA-256(PIN), 16)`, the PIN hash defined by CTAP. tpm-fido checks a PIN by reading the index with that authorization value. The PIN hash is never stored on disk.
* The index's single byte of data is the remaining PIN retries. It is decremented before each check and reset after a correct PIN. After 8 wrong PINs the PIN is blocked; after 3 in a row tpm-fido must be restarted (the equivalent of unplugging a security key).
* The index doesn't have `noDA` set, so every wrong PIN also counts towards the TPM's dictionary attack lockout. This limits guessing even for software that talks to the TPM directly instead of going through tpm-fido. While the TPM is in lockout, PIN checks fail with `PIN_AUTH_BLOCKED` without using up a retry. Note that the lockout is TPM-wide: wrong FIDO PINs also count towards the lockout of other DA-protected objects (for example a TPM+PIN LUKS key), and vice versa. `tpm2_getcap properties-variable` shows the TPM's `MAX_AUTH_FAIL` and `LOCKOUT_INTERVAL`.
* The lockout only limits guessing if the TPM's lockout authorization is set (`tpm2_changeauth -c lockout`). With an empty lockout authorization, anyone who can use the TPM can reset the lockout counter (`tpm2_dictionarylockout -c`) and guess without limit. The retries counter doesn't help either: it can be rewritten with the (empty) owner authorization.

Limitations:

* The PIN only gates what tpm-fido does. The credential keys aren't bound to the PIN, so software running as your user can still use them through the TPM directly.
* The PIN hash is sent to the TPM in a password session, so it is visible on the bus to an attacker with physical access to a discrete TPM.
* A blocked or forgotten PIN is removed by resetting the authenticator. Deleting only the PIN index (`tpm2_nvundefine -C o 0x0100F1D1`) also removes the PIN and keeps the existing credentials, but it destroys the UV key, so every hmac-secret secret that was derived with user verification (for example a LUKS key enrolled with `--fido2-with-client-pin=yes`) is lost.

### hmac-secret

Credentials created with the `hmac-secret` extension can derive secrets from salts, which is what `systemd-cryptenroll --fido2-device`, `age-plugin-fido2-hmac` and similar tools use. Each credential has two secrets (`CredRandomWithoutUV` and `CredRandomWithUV` in CTAP 2.1). tpm-fido derives them by HMACing the relying party and credential ID with one of two TPM keys:

* Without user verification: the device key. It never leaves the TPM and is destroyed by a reset or when the TPM is cleared, but it has an empty authorization value, so **anyone who can use the TPM can recompute these secrets**, including someone who boots another OS on the machine. The credential ID is not secret (systemd stores it in the LUKS header).
* With user verification (a PIN): an ordinary keyed hash key whose authorization value is the PIN hash. It is stored, wrapped by the TPM, in the PIN index. Computing these secrets requires the PIN, even with direct access to the TPM, and guessing it counts towards the TPM's dictionary attack lockout. Changing the PIN re-wraps the same key (`TPM2_ObjectChangeAuth`), so the secrets survive PIN changes.

For disk encryption, enroll with a PIN:

```
systemd-cryptenroll --fido2-device=auto --fido2-with-client-pin=yes /dev/sdXn
```

Both secrets are lost when the authenticator is reset or the TPM is cleared or replaced, so keep another way to unlock (a recovery key or passphrase).

tpm-fido keeps the PIN hash in memory while the PIN token it was issued for is valid (until the next `getPinToken`, PIN change or restart), because the UV key needs it at assertion time.

### Signature counter

The signature counter is a TPM NV counter at index `0x0100F1D0` (change it with `-counter-index`). tpm-fido defines the index on first start, which requires the owner hierarchy to have an empty authorization value. The index is an orderly (hybrid) counter, so the TPM doesn't write NV on every signature. After an unclean shutdown the counter jumps forward.

Older versions of tpm-fido reported the number of seconds since 2021-01-01 as the counter. The NV counter value is offset by `0x10000000` so it stays above any of those values.

## Status

tpm-fido has been tested to work with Chrome and Firefox on Linux.

CTAP2 support has been tested with libfido2 (`fido2-cred`, `fido2-assert`, `fido2-token`) and python-fido2 against swtpm. To run against swtpm:

```
swtpm socket --tpm2 --tpmstate dir=/tmp/swtpm --server type=unixio,path=/tmp/swtpm/sock --flags not-need-init,startup-clear
./tpm-fido -device /tmp/swtpm/sock
```

## Building

```
# in the root directory of tpm-fido run:
go build
```

## Running

In order to run `tpm-fido` you will need permission to access `/dev/tpmrm0`. On Ubuntu and Arch, you can add your user to the `tss` group.

Your user also needs permission to access `/dev/uhid` so that `tpm-fido` can appear to be a USB device.
I use the following udev rule to set the appropriate `uhid` permissions:

```
KERNEL=="uhid", SUBSYSTEM=="misc", GROUP="SOME_UHID_GROUP_MY_USER_BELONGS_TO", MODE="0660"
```

To ensure the above udev rule gets triggered, I also add the `uhid` module to `/etc/modules-load.d/uhid.conf` so that it loads at boot.

tpm-fido creates the following TPM objects, which requires the owner hierarchy to have an empty authorization value:

| Handle | Contents | Created |
|---|---|---|
| `0x0100F1D0` | signature counter | on first start |
| `0x0100F1D1` | PIN and UV key | when a PIN is set |
| `0x0100F1D2` | state flags | on the first reset |
| `0x8100F1D0` | device key (persistent) | on first start |

To run:

```
# as a user that has permission to read and write to /dev/tpmrm0:
./tpm-fido
```
Note: do not run with `sudo` or as root, as it will not work.

## Dependencies

tpm-fido requires `pinentry` to be available on the system. If you have gpg installed you most likely already have `pinentry`.
