# SSH keys and GNOME's SSH agent

`ssh-keygen -t ecdsa-sk` works with tpm-fido; with `-O verify-required` every signature also needs the PIN. ssh asks for the PIN in the terminal, but an SSH agent has no terminal and asks through `SSH_ASKPASS`; without one it refuses to sign ("agent refused operation"). GNOME's agent (`gcr-ssh-agent`, `SSH_AUTH_SOCK=/run/user/$UID/gcr/ssh`) has none configured.

`tpm-fido-askpass` is an askpass program for GNOME. To use it with GNOME's agent:

```
make install
make enable-gnome-ssh   # adds a drop-in to gcr-ssh-agent.service and restarts it
```

* **Security key PINs:** if tpm-fido runs, tpm-fido-askpass asks it for the PIN over D-Bus (`io.github.psanford.TpmFido`), and tpm-fido shows a single "Sign In with SSH Key?" prompt. Typing the PIN into a prompt tpm-fido showed proves that you are present, so the signature that follows doesn't show tpm-fido's confirmation dialog: one prompt instead of two. This presence grant is used once, expires after 15 seconds, only applies to SSH (relying party IDs starting with `ssh:`) and to a request whose verified PIN is the one you typed. tpm-fido doesn't hand the PIN to tpm-fido-askpass: it returns a random one-time token, which the SSH agent sends to tpm-fido in place of the PIN. tpm-fido recognizes it and checks the real PIN, which never leaves tpm-fido, against the TPM; the resulting PIN token is only valid for SSH. Other programs can ask tpm-fido to show the prompt (as they could show any prompt), but can't answer it, and if you type your PIN into a prompt they triggered, they get at most one SSH signature, not your PIN. tpm-fido-askpass only talks to tpm-fido if its D-Bus name belongs to the `tpm-fido` binary installed next to it (`$TPMFIDO_PATH` overrides the path), so another program claiming the name while tpm-fido isn't running doesn't get the PIN. Without tpm-fido (e.g. for a hardware key), it asks with the GNOME system prompt; the PIN travels from the prompt encrypted with gcr's secret exchange. Disable the combined prompt with `tpm-fido -askpass-service=false`.
* **Key passphrases and `ssh-add -c` confirmations:** GNOME system prompt. gcr-ssh-agent's own passphrase prompts for keys in `~/.ssh` (with "remember in keyring") are unaffected: gcr runs `ssh-add` with its own askpass.
* **"Touch your security key":** a desktop notification, unless tpm-fido handles the request (it shows its own dialog).
* Without a GNOME system prompter it runs `$TPMFIDO_ASKPASS_FALLBACK` or OpenSSH's `ssh-askpass`.

`make disable-gnome-ssh` removes the drop-in. It also works with OpenSSH's own agent: set `SSH_ASKPASS` to `tpm-fido-askpass` and `SSH_ASKPASS_REQUIRE=force` in its environment.
