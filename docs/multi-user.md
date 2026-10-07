# Several users and TPM objects

## Several users

Every member of the `tss` group can use the TPM directly, and the owner hierarchy has an empty authorization value, so tpm-fido can't rely on the TPM's access control between users. Instead, each user has

* their own TPM objects, in a slot derived from their user ID (`-slot` chooses another; user IDs above 65535 must choose one), and
* a random user secret in `~/.local/share/tpm-fido/user-secret`. The device key's authorization value and the PIN's authorization values in the TPM are derived from it.

Every credential, the hmac-secret secrets and the passkey store depend on the device key, so another user of the TPM who can't read your user secret can't use your credentials, compute your hmac-secret secrets (e.g. LUKS keys), read your passkeys or even start guessing your PIN. tpm-fido refuses to start if the device key in its slot doesn't accept its user secret (another user's slot, or a replaced user secret file).

Other users can still delete your TPM objects, which destroys your credentials but doesn't give access to them. Credentials registered with upstream tpm-fido (legacy key handles) depend only on the credential ID and aren't protected; reset the security key to retire them.

**Don't lose `~/.local/share/tpm-fido`.** Without the user secret, none of your credentials can be used anymore. A backup only helps on the same TPM.

## TPM objects

tpm-fido creates these TPM objects, which requires the owner hierarchy to have an empty authorization value. For slot *s* (by default your user ID):

| Handle | Contents | Created |
|---|---|---|
| `0x01300000 + 4s` | signature counter | on first start |
| `0x01300000 + 4s + 1` | PIN and UV key | when a PIN is set |
| `0x01300000 + 4s + 2` | state flags | on the first reset |
| `0x01300000 + 4s + 3` | passkey store counter | on first start |
| `0x81300000 + s` | device key (persistent) | on first start |
| `0x81310000` | storage root key, shared by all users (no secrets) | on first start, unless the TPM already has it at `0x81000001` or `0x81000002` |

For user ID 1000: `0x01300FA0`–`0x01300FA3` and `0x813003E8`. Development versions used fixed handles (`0x0100F1D0`–`0x0100F1D2`, `0x8100F1D0`) for everyone; tpm-fido mentions them at startup if they are still there.
