# tpm-fido

tpm-fido is FIDO token implementation for Linux that protects the token keys by using your system's TPM. tpm-fido uses Linux's [uhid](https://github.com/psanford/uhid) facility to emulate a USB HID device so that it is properly detected by browsers.

##  Implementation details

tpm-fido uses the TPM 2.0 API. The overall design is as follows:

On registration tpm-fido generates a new P256 primary key under the Owner hierarchy on the TPM. To ensure that the key is unique per site and registration, tpm-fido generates a random 20 byte seed for each registration. The primary key template is populated with unique values from a sha256 hkdf of the 20 byte random seed and the application parameter provided by the browser.

A signing child key is then generated from that primary key. The key handle returned to the caller is a concatenation of the child key's public and private key handles and the 20 byte seed.

On an authentication request, tpm-fido will attempt to load the primary key by initializing the hkdf in the same manner as above. It will then attempt to load the child key from the provided key handle. Any incorrect values or values created by a different TPM will fail to load.

### FIDO2 (CTAP2)

tpm-fido speaks both U2F (CTAP1) and CTAP 2.0. The CTAP2 `rpIdHash` is the same value as the U2F application parameter, so CTAP2 credential IDs use the key handle format described above, and credentials registered over U2F keep working over CTAP2.

Supported: `authenticatorMakeCredential` (ES256 only, "packed" self attestation), `authenticatorGetAssertion`, `authenticatorGetInfo` and `authenticatorClientPIN` (PIN protocols 1 and 2). Not supported yet: discoverable (resident) credentials, `authenticatorReset` and extensions such as `hmac-secret`.

User presence is confirmed through `pinentry`, with the relying party ID and user name shown in the prompt.

New key handles set `noDA` on their keys. The keys have an empty authorization value, so dictionary attack protection doesn't protect anything, and without `noDA` the TPM refuses to use them while it is in lockout. Key handles created by earlier versions keep working but can't be used during a lockout.

### PIN

The PIN is set, entered and changed by the platform (browser, `fido2-token -S`, ...), as with a hardware security key. Once a PIN is set, every registration requires it (CTAP 2.0); sign-ins require it when the site asks for user verification.

The PIN is stored in the TPM in NV index `0x0100F1D1` (change it with `-pin-index`):

* The index's authorization value is `LEFT(SHA-256(PIN), 16)`, the PIN hash defined by CTAP. tpm-fido checks a PIN by reading the index with that authorization value. The PIN hash is never stored on disk.
* The index's single byte of data is the remaining PIN retries. It is decremented before each check and reset after a correct PIN. After 8 wrong PINs the PIN is blocked; after 3 in a row tpm-fido must be restarted (the equivalent of unplugging a security key).
* The index doesn't have `noDA` set, so every wrong PIN also counts towards the TPM's dictionary attack lockout. This limits guessing even for software that talks to the TPM directly instead of going through tpm-fido. While the TPM is in lockout, PIN checks fail with `PIN_AUTH_BLOCKED` without using up a retry. Note that the lockout is TPM-wide: wrong FIDO PINs also count towards the lockout of other DA-protected objects (for example a TPM+PIN LUKS key), and vice versa. `tpm2_getcap properties-variable` shows the TPM's `MAX_AUTH_FAIL` and `LOCKOUT_INTERVAL`.

Limitations:

* The PIN only gates what tpm-fido does. The credential keys aren't bound to the PIN, so software running as your user can still use them through the TPM directly.
* The PIN hash is sent to the TPM in a password session, so it is visible on the bus to an attacker with physical access to a discrete TPM.
* There is no `authenticatorReset`. To remove a blocked or forgotten PIN, delete the index with `tpm2_nvundefine -C o 0x0100F1D1`. Unlike a reset, this keeps the existing credentials.

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

To run:

```
# as a user that has permission to read and write to /dev/tpmrm0:
./tpm-fido
```
Note: do not run with `sudo` or as root, as it will not work.

## Dependencies

tpm-fido requires `pinentry` to be available on the system. If you have gpg installed you most likely already have `pinentry`.
