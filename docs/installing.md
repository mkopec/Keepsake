# Installing

```
make install               # as the user who will use keepsake; no root needed
sudo make install-system   # once per machine, then log out and back in
make enable                # start keepsake now and with every graphical login
```

* `make install` builds Keepsake and installs it, the Security Keys app and the systemd user service under `~/.local` and `~/.config`. `make check-deps` reports missing dependencies and permissions.
* `sudo make install-system` installs a udev rule that gives the user logged in at the local desktop access to `/dev/uhid` (so Keepsake can appear as a USB security key), loads the `uhid` module at boot, and adds you (`$SUDO_USER`, or `TPM_USER=<name>`) to the `tss` group, which may use `/dev/tpmrm0`. Access to `/dev/uhid` allows creating any HID device, including keyboards; the rule limits it to the active local session. Without a local session (e.g. over SSH), use `GROUP="<a group you are in>", MODE="0660"` instead of `TAG+="uaccess"` in `/etc/udev/rules.d/70-uhid.rules`.
* Set the TPM's lockout authorization (`tpm2_changeauth -c lockout <password>`) so the TPM's dictionary attack protection actually limits PIN guessing.
* `make uninstall` and `sudo make uninstall-system` remove the files again. Credentials are kept: they are in the TPM and `~/.local/share/keepsake`.

Packagers can set `PREFIX=/usr` and `DESTDIR`. Run Keepsake as the user, not as root.

## Dependencies

Outside GNOME, Keepsake requires `pinentry` to be available on the system. If you have gpg installed you most likely already have `pinentry`.
