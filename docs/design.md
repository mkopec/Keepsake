# Design

How tpm-fido derives, stores and uses credential keys in the TPM.

## Key handles

tpm-fido uses the TPM 2.0 API. The overall design is as follows:

On registration tpm-fido generates a new P256 primary key under the Owner hierarchy on the TPM. To ensure that the key is unique per site and registration, tpm-fido generates a random 20 byte seed for each registration. The primary key template is populated with unique values from a sha256 hkdf of the 20 byte random seed and the application parameter provided by the browser.

A signing child key is then generated from that primary key. The key handle returned to the caller is a concatenation of the child key's public and private key handles and the 20 byte seed.

On an authentication request, tpm-fido will attempt to load the primary key by initializing the hkdf in the same manner as above. It will then attempt to load the child key from the provided key handle. Any incorrect values or values created by a different TPM will fail to load.

## Device key

Current versions add a device key: a keyed hash key with a TPM generated secret, made persistent in your slot (see [TPM objects](multi-user.md#tpm-objects)), with an authorization value derived from your user secret, whose wrapped private area is discarded. Instead of the random seed itself, the primary key template uses an HMAC, computed with the device key, of the seed and a version byte. The version byte records whether the credential was created with `hmac-secret`, whether it is a passkey and its `credProtect` level. Because the version byte is part of the HMAC, a credential ID whose flags were modified doesn't load. (Development versions before this used a format that didn't authenticate the flags, which let a deleted passkey be used again by clearing its "passkey" flag; their credential IDs are no longer accepted.)

Because the device key can't be loaded again once it is evicted from the TPM, replacing it (`authenticatorReset`) irrecoverably invalidates every credential created with it. Key handles from versions without a device key ("legacy" key handles) keep working until the first reset; the reset sets a flag in your slot's state index that disables them for you.

Software running as you can read the user secret and so use the device key; other users can't (see [Several users](multi-user.md#several-users)).

New key handles also set `noDA` on their keys. The keys have an empty authorization value, so dictionary attack protection doesn't protect anything, and without `noDA` the TPM refuses to use them while it is in lockout. Legacy key handles can't be used during a lockout.

## FIDO2 (CTAP2)

tpm-fido speaks both U2F (CTAP1) and CTAP 2.0. The CTAP2 `rpIdHash` is the same value as the U2F application parameter, so CTAP2 credential IDs use the key handle format described above, and credentials registered over U2F keep working over CTAP2.

Supported: `authenticatorMakeCredential` (ES256 only, "packed" self attestation), `authenticatorGetAssertion` and `authenticatorGetNextAssertion` (including discoverable credentials, i.e. passkeys), `authenticatorGetInfo`, `authenticatorClientPIN` (PIN protocols 1 and 2), `authenticatorReset`, the credential management preview command of `FIDO_2_1_PRE` authenticators, and the `hmac-secret` and `credProtect` extensions.

User presence is confirmed in a dialog showing the relying party ID and user name (see [Desktop integration](desktop.md)).

## Signature counter

The signature counter is a TPM NV counter in your slot. tpm-fido defines the index on first start, which requires the owner hierarchy to have an empty authorization value. The index is an orderly (hybrid) counter, so the TPM doesn't write NV on every signature. After an unclean shutdown the counter jumps forward.

Older versions of tpm-fido reported the number of seconds since 2021-01-01 as the counter. The NV counter value is offset by `0x10000000` so it stays above any of those values.
