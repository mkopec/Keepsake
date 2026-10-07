# PIN and user verification

## PIN

The PIN is set, entered and changed by the platform (browser, `fido2-token -S`, ...), as with a hardware security key. Once a PIN is set, every registration requires it (CTAP 2.0); sign-ins require it when the site asks for user verification. U2F can't ask for a PIN, so U2F registrations are refused once a PIN is set (browsers use CTAP2; U2F sign-ins with existing credentials keep working). A verified PIN is valid for one minute; then tpm-fido wipes the PIN hash from memory.

The PIN is stored in the TPM in your slot's PIN index (see [TPM objects](multi-user.md#tpm-objects)):

* The index's authorization value is derived from `LEFT(SHA-256(PIN), 16)`, the PIN hash defined by CTAP, and your user secret. tpm-fido checks a PIN by reading the index with that authorization value. The PIN hash is never stored on disk.
* The index's single byte of data is the remaining PIN retries. It is decremented before each check and reset after a correct PIN. After 8 wrong PINs the PIN is blocked; after 3 in a row tpm-fido must be restarted (the equivalent of unplugging a security key).
* The index doesn't have `noDA` set, so every wrong PIN also counts towards the TPM's dictionary attack lockout. This limits guessing even for software that talks to the TPM directly instead of going through tpm-fido. While the TPM is in lockout, PIN checks fail with `PIN_AUTH_BLOCKED` without using up a retry. Note that the lockout is TPM-wide: wrong FIDO PINs also count towards the lockout of other DA-protected objects (for example a TPM+PIN LUKS key), and vice versa. `tpm2_getcap properties-variable` shows the TPM's `MAX_AUTH_FAIL` and `LOCKOUT_INTERVAL`.
* The lockout only limits guessing if the TPM's lockout authorization is set (`tpm2_changeauth -c lockout`). With an empty lockout authorization, anyone who can use the TPM can reset the lockout counter (`tpm2_dictionarylockout -c`) and guess without limit. The retries counter doesn't help either: it can be rewritten with the (empty) owner authorization.
  tpm-fido warns at startup when the lockout authorization isn't set.

Limitations:

* The PIN only gates what tpm-fido does, except for credentials created with `credProtect` level 3 (see below). The keys of other credentials aren't bound to the PIN, so software running as your user can still use them through the TPM directly.
* A blocked or forgotten PIN is removed by resetting the authenticator. Deleting only the PIN index (`tpm2_nvundefine -C o <PIN index>`) also removes the PIN and keeps the existing credentials, but it destroys the UV key, so every hmac-secret secret that was derived with user verification (for example a LUKS key enrolled with `--fido2-with-client-pin=yes`) is lost.

## credProtect: credentials bound to the PIN

A relying party can create a credential with the `credProtect` extension. Level 2 (`userVerificationOptionalWithCredentialIDList`) passkeys are only discovered after the PIN was entered. Level 3 (`userVerificationRequired`) credentials can only be used with the PIN, and tpm-fido enforces this in the TPM: the credential key has no usable authorization value, only a policy (`TPM2_PolicySecret`) that requires the UV key, whose authorization value is the PIN hash. So even software that talks to the TPM directly can't sign with it without the PIN, and every wrong guess counts towards the TPM's dictionary attack lockout.

* Level 3 needs a PIN to be set when the credential is created.
* The binding survives PIN changes (the UV key is re-wrapped, not replaced), but not removing the PIN index: a new PIN creates a new UV key.
* Level 3 credential IDs are 279 bytes, too long for U2F.
* Without the PIN, level 3 credentials are invisible: they aren't returned, and aren't recognized in an allowList or excludeList.

Request it with `fido2-cred -M -c 3`, the `credentialProtectionPolicy: "userVerificationRequired"` WebAuthn extension, or (depending on the OpenSSH version) `ssh-keygen -t ecdsa-sk -O verify-required`.
