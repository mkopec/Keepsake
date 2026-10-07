# hmac-secret (disk encryption and key derivation)

Credentials created with the `hmac-secret` extension can derive secrets from salts, which is what `systemd-cryptenroll --fido2-device`, `age-plugin-fido2-hmac` and similar tools use. Each credential has two secrets (`CredRandomWithoutUV` and `CredRandomWithUV` in CTAP 2.1). Keepsake derives them by HMACing the relying party and credential ID with one of two TPM keys:

* Without user verification: the device key. It never leaves the TPM and is destroyed by a reset or when the TPM is cleared. Using it needs your user secret, so other users of the TPM can't compute these secrets, but **anyone who can read your files and use the TPM can**: software running as you, or someone who boots another OS on the machine while your home directory isn't encrypted. The credential ID is not secret (systemd stores it in the LUKS header).
* With user verification (a PIN): an ordinary keyed hash key whose authorization value is the PIN hash. It is stored, wrapped by the TPM, in the PIN index. Computing these secrets requires the PIN, even with direct access to the TPM, and guessing it counts towards the TPM's dictionary attack lockout. Changing the PIN re-wraps the same key (`TPM2_ObjectChangeAuth`), so the secrets survive PIN changes.

For disk encryption, enroll with a PIN:

```
systemd-cryptenroll --fido2-device=auto --fido2-with-client-pin=yes /dev/sdXn
```

Both secrets are lost when the authenticator is reset or the TPM is cleared or replaced, so keep another way to unlock (a recovery key or passphrase).

Keepsake keeps the PIN hash in memory while the PIN token it was issued for is valid (until the next `getPinToken`, PIN change or restart), because the UV key needs it at assertion time.
