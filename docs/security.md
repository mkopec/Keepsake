# Security

tpm-fido protects against copying the credentials: the private keys never leave the TPM, and credential IDs and the passkey store are useless without this TPM and your user secret. It also limits PIN guessing with the TPM's dictionary attack protection, binds `credProtect` level 3 credentials to the PIN in the TPM, keeps other users of the TPM away from your credentials, and protects secrets on the bus of a discrete TPM.

It doesn't protect against:

* **Programs that can open the security key device.** The device node (`/dev/hidrawN`) is the boundary: any program that can open it can make requests, as with a USB security key, and sees every response. On most systems only the logged in user can open it (`uaccess`), but check for udev rules that make all hidraw devices world-writable (`MODE="0666"`).
* **Malware running as you.** It can read your user secret and use credentials (except level 3 ones, without the PIN) directly through the TPM, while it runs; it can't copy the private keys. On X11 it can also click dialogs.
* **Someone booting another OS on the machine** while your home directory isn't encrypted: they can read the user secret and use the credentials the same way. Use full disk encryption; `-bind-boot-state` can help (see [Boot state binding](#boot-state-binding)).
* **Unlimited PIN guessing and clearing the TPM**, if the TPM's lockout authorization is empty (tpm-fido warns at startup): anyone who can use the TPM can reset its dictionary attack counter, or clear the TPM, destroying all its keys. Set it with `tpm2_changeauth -c lockout <password>`.
* **Other users of the TPM deleting your TPM objects**, which destroys your credentials (but doesn't give access to them).

By default the log doesn't contain relying party IDs or user names (`-verbose` adds them).

## Bus encryption

Someone with physical access can record the bus between the CPU and a discrete TPM chip (firmware TPMs, e.g. Intel PTT or AMD fTPM, have no such bus). tpm-fido limits what such a recording is good for:

* PIN hashes, hmac-secret outputs, the passkey store key and the authorization values of the device key and credential keys only cross the bus encrypted, in HMAC sessions salted with the TPM's storage root key, or not at all (an HMAC session proves knowledge of a value without sending it).
* The recording does show the template of each credential's parent key, so the recorder can load the credential key into the TPM later, but signing needs the credential key's authorization value. Credential IDs created by development versions before credential keys had one (format `0x20`) can be used with a recording; register them again to replace them.
* Signatures and credential IDs aren't secret and aren't encrypted.

To protect against an active interposer, the storage root key's name is pinned on first use in `srk-name` next to the passkey store; if it changes, tpm-fido refuses to start. (It also changes when the TPM is cleared, which destroys all tpm-fido credentials anyway; delete the file then.) An interposer present the first time tpm-fido runs isn't detected.

## Boot state binding

With `-bind-boot-state`, the device key created at the next reset (or first start) is bound to PCR 7, which records the Secure Boot state and the keys that verified the boot chain. Then credentials can only be used after a boot with the same Secure Boot configuration, which helps against someone who boots another OS on the machine to use them (see [Security](#security)). It only helps if PCR 7 differs for that OS: typically when you enroll your own Secure Boot keys (e.g. with sbctl) instead of using Microsoft's, and not at all with Secure Boot disabled.

Changing the Secure Boot configuration (enrolling keys, updating dbx, some firmware updates) makes every credential unusable until it is restored; tpm-fido warns at startup. The only other way out is a reset, which loses all credentials, so keep another way to sign in.
