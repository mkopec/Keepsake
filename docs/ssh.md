# SSH keys and GNOME's SSH agent

`ssh-keygen -t ecdsa-sk` works with Keepsake; with `-O verify-required` every signature also needs the PIN. ssh asks for the PIN in the terminal, but an SSH agent has no terminal and asks through `SSH_ASKPASS`; without one it refuses to sign ("agent refused operation"). GNOME's agent (`gcr-ssh-agent`, `SSH_AUTH_SOCK=/run/user/$UID/gcr/ssh`) has none configured.

`keepsake-askpass` is an askpass program for GNOME. To use it with GNOME's agent:

```
make install
make enable-gnome-ssh   # adds a drop-in to gcr-ssh-agent.service and restarts it
```

* **Security key PINs:** if Keepsake runs, keepsake-askpass asks it for the PIN over D-Bus (`io.github.mkopec.Keepsake.Daemon`), and Keepsake shows a single "Sign In with SSH Key?" prompt. Typing the PIN into a prompt Keepsake showed proves that you are present, so the signature that follows doesn't show Keepsake's confirmation dialog: one prompt instead of two. This presence grant is used once, expires after 15 seconds, only applies to SSH (relying party IDs starting with `ssh:`) and to a request whose verified PIN is the one you typed. Keepsake doesn't hand the PIN to keepsake-askpass: it returns a random one-time token, which the SSH agent sends to Keepsake in place of the PIN. Keepsake recognizes it and checks the real PIN, which never leaves Keepsake, against the TPM; the resulting PIN token is only valid for SSH. Other programs can ask Keepsake to show the prompt (as they could show any prompt), but can't answer it, and if you type your PIN into a prompt they triggered, they get at most one SSH signature, not your PIN. keepsake-askpass only talks to Keepsake if its D-Bus name belongs to the `keepsake` binary installed next to it (`$KEEPSAKE_PATH` overrides the path), so another program claiming the name while Keepsake isn't running doesn't get the PIN. Without Keepsake (e.g. for a hardware key), it asks with the GNOME system prompt; the PIN travels from the prompt encrypted with gcr's secret exchange. Disable the combined prompt with `keepsake -askpass-service=false`.
* **Key passphrases and `ssh-add -c` confirmations:** GNOME system prompt. gcr-ssh-agent's own passphrase prompts for keys in `~/.ssh` (with "remember in keyring") are unaffected: gcr runs `ssh-add` with its own askpass.
* **"Touch your security key":** a desktop notification, unless Keepsake handles the request (it shows its own dialog).
* Without a GNOME system prompter it runs `$KEEPSAKE_ASKPASS_FALLBACK` or OpenSSH's `ssh-askpass`.

`make disable-gnome-ssh` removes the drop-in. It also works with OpenSSH's own agent: set `SSH_ASKPASS` to `keepsake-askpass` and `SSH_ASKPASS_REQUIRE=force` in its environment.
