# Passkeys and reset

## Passkeys

Discoverable credentials (passkeys) are credentials like any other, flagged as discoverable. Their metadata (relying party, user ID, user name and display name, public key) is stored in `$XDG_DATA_HOME/keepsake/passkeys` (`~/.local/share/keepsake/passkeys`, change it with `-passkey-store`). The file is encrypted with AES-256-GCM using a key derived from the device key, so it can only be read with this TPM.

A passkey can only be used while it is in the store, so deleting a passkey revokes it, even for a site that still knows its credential ID. Registering a new passkey for the same site and user replaces (and revokes) the old one. Up to 128 passkeys can be stored. If the store can't be decrypted (because the TPM was cleared, for example), it is moved aside to `passkeys.undecryptable-<time>` and a new one is started.

The store records the value of a TPM counter that Keepsake advances on every save, so an older copy of the store (e.g. restored from a backup) is detected, moved aside the same way and not used: it could bring back passkeys you deleted. Back up the store only to restore it after losing the newer one, and expect Keepsake to refuse it.

When a site asks for a passkey without user verification, only the user ID is returned; user names are only returned after the PIN was verified (CTAP 2.0).

Passkeys can be listed and deleted with tools that support credential management, for example `fido2-token -L -r`, `fido2-token -L -k <rp id>` and `fido2-token -D -i <credential id>`, or Chrome's security key settings. These require the PIN.

## Reset

`authenticatorReset` (for example `fido2-token -R`, or "Reset your security key" in Chrome) replaces the device key, disables legacy key handles, removes the PIN and deletes the passkey store. Every credential stops working, including hmac-secret secrets, so LUKS keys enrolled with Keepsake are lost. Hardware authenticators only accept a reset shortly after being plugged in; Keepsake instead asks for confirmation in a dialog.
