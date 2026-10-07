"""Security key operations for keepsake-settings, using standard CTAP2
commands through python-fido2, so they work with Keepsake and with hardware
security keys."""

import random
import time
from dataclasses import dataclass

from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2
from fido2.ctap2.credman import CredentialManagement
from fido2.ctap2.pin import ClientPin
from fido2.hid import CAPABILITY, ConnectionFailure, CtapHidDevice, list_descriptors, open_connection

KEEPSAKE_VID, KEEPSAKE_PID = 0x15D9, 0x0A37

ERR = CtapError.ERR


class SecurityKeyError(Exception):
    """An error with a message meant for the user."""


def describe_error(e: CtapError, retries: int | None = None) -> str:
    code = e.code
    if code == ERR.PIN_INVALID:
        if retries is not None:
            return f"Incorrect PIN. {retries} attempt{'s' if retries != 1 else ''} left."
        return "Incorrect PIN."
    if code == ERR.PIN_BLOCKED:
        return "The PIN is blocked after too many incorrect attempts. Reset the security key to use it again."
    if code == ERR.PIN_AUTH_BLOCKED:
        return "Too many incorrect PINs. Unplug the security key (or restart Keepsake) and try again."
    if code == ERR.PIN_POLICY_VIOLATION:
        return "The security key doesn’t accept this PIN. Use at least 4 characters."
    if code in (ERR.OPERATION_DENIED, ERR.KEEPALIVE_CANCEL):
        return "The request was cancelled on the security key."
    if code == ERR.USER_ACTION_TIMEOUT:
        return "The security key wasn’t confirmed in time."
    if code == ERR.NOT_ALLOWED:
        return "The security key refused the request. Hardware keys can only be reset within a few seconds of being plugged in."
    return f"The security key reported an error ({code.name if hasattr(code, 'name') else hex(code)})."


MIN_PIN_LENGTH = 4


def check_new_pin(pin: str):
    """Checks the length limits of CTAP: at least 4 characters and at most
    63 bytes."""
    if len(pin) < MIN_PIN_LENGTH:
        raise SecurityKeyError(f"The PIN must have at least {MIN_PIN_LENGTH} characters.")
    if len(pin.encode()) > 63:
        raise SecurityKeyError("The PIN is too long.")


@dataclass
class Passkey:
    rp_id: str
    user_name: str
    display_name: str
    credential_id: bytes


class SecurityKey:
    def __init__(self, dev: CtapHidDevice):
        self.dev = dev
        self.ctap = Ctap2(dev)

    @property
    def path(self) -> str:
        return self.dev.descriptor.path

    @property
    def is_keepsake(self) -> bool:
        d = self.dev.descriptor
        return (d.vid, d.pid) == (KEEPSAKE_VID, KEEPSAKE_PID)

    @property
    def name(self) -> str:
        if self.is_keepsake:
            return "TPM Security Key"
        return self.dev.descriptor.product_name or "Security Key"

    def refresh(self):
        self.ctap = Ctap2(self.dev)

    @property
    def pin_supported(self) -> bool:
        return ClientPin.is_supported(self.ctap.info)

    @property
    def pin_set(self) -> bool:
        return bool(self.ctap.info.options.get("clientPin"))

    @property
    def passkeys_supported(self) -> bool:
        return CredentialManagement.is_supported(self.ctap.info)

    def pin_retries(self) -> int:
        return ClientPin(self.ctap).get_pin_retries()[0]

    def set_pin(self, pin: str):
        check_new_pin(pin)
        self._call(lambda: ClientPin(self.ctap).set_pin(pin))
        self.refresh()

    def change_pin(self, old: str, new: str):
        check_new_pin(new)
        self._call(lambda: ClientPin(self.ctap).change_pin(old, new))

    def _credman(self, pin: str) -> CredentialManagement:
        cp = ClientPin(self.ctap)
        token = self._call(lambda: cp.get_pin_token(pin, ClientPin.PERMISSION.CREDENTIAL_MGMT))
        return CredentialManagement(self.ctap, cp.protocol, token)

    def passkeys(self, pin: str) -> list[Passkey]:
        cm = self._credman(pin)
        out = []
        for rp in self._call(cm.enumerate_rps):
            rp_id = rp[CredentialManagement.RESULT.RP]["id"]
            rp_hash = rp[CredentialManagement.RESULT.RP_ID_HASH]
            for cred in self._call(lambda: cm.enumerate_creds(rp_hash)):
                user = cred[CredentialManagement.RESULT.USER]
                out.append(Passkey(
                    rp_id=rp_id,
                    user_name=user.get("name", ""),
                    display_name=user.get("displayName", ""),
                    credential_id=cred[CredentialManagement.RESULT.CREDENTIAL_ID]["id"],
                ))
        out.sort(key=lambda p: (p.rp_id, p.user_name))
        return out

    def delete_passkey(self, pin: str, passkey: Passkey):
        cm = self._credman(pin)
        self._call(lambda: cm.delete_cred({"type": "public-key", "id": passkey.credential_id}))

    def reset(self):
        self._call(self.ctap.reset)
        self.refresh()

    def _call(self, fn):
        try:
            return fn()
        except CtapError as e:
            retries = None
            if e.code == ERR.PIN_INVALID:
                try:
                    retries = self.pin_retries()
                except Exception:
                    pass
            raise SecurityKeyError(describe_error(e, retries)) from e


    def close(self):
        self.dev.close()


def _transient(e: Exception) -> bool:
    """Reports whether e is caused by another program (or another channel of
    this one) using the key at the same time. Every program that opens a key
    sees all of its responses, so a busy key can also show up as a response
    for the wrong channel or nonce."""
    return isinstance(e, ConnectionFailure) or (isinstance(e, CtapError) and e.code == ERR.CHANNEL_BUSY)


def _open(descriptor, attempts=6) -> SecurityKey | None:
    """Opens a CTAP2 key, retrying while it is busy. Returns None for
    U2F-only keys, which have no PIN or passkeys to manage."""
    for i in range(attempts):
        conn = open_connection(descriptor)
        try:
            dev = CtapHidDevice(descriptor, conn)
            if not dev.capabilities & CAPABILITY.CBOR:
                conn.close()
                return None
            return SecurityKey(dev)
        except Exception as e:
            conn.close()
            if not _transient(e) or i == attempts - 1:
                raise
            # random backoff, so programs retrying together don't collide
            # again
            time.sleep(random.uniform(0.05, 0.15) * (i + 1))


def list_keys() -> tuple[list[SecurityKey], list[str]]:
    """Returns the CTAP2 security keys, and messages about keys that couldn't
    be read."""
    keys, errors = [], []
    for d in list_descriptors():
        try:
            key = _open(d)
        except Exception as e:
            errors.append(f"Couldn’t read {d.product_name or 'a security key'}: {e}")
            continue
        if key is not None:
            keys.append(key)
    # Keepsake first
    keys.sort(key=lambda k: not k.is_keepsake)
    return keys, errors
