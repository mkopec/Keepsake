# Testing

tpm-fido has been tested to work with Chrome and Firefox on Linux.

CTAP2 support has been tested with libfido2 (`fido2-cred`, `fido2-assert`, `fido2-token`) and python-fido2 against swtpm. To run against swtpm:

```
mkdir -p /tmp/swtpm
swtpm socket --tpm2 --tpmstate dir=/tmp/swtpm --server type=unixio,path=/tmp/swtpm/sock --ctrl type=unixio,path=/tmp/swtpm/sock.ctrl --flags not-need-init,startup-clear
./tpm-fido -device /tmp/swtpm/sock
```

The TPM tests (`make check TPMFIDO_SWTPM=/tmp/swtpm/sock`) deliberately enter a few wrong PINs. swtpm locks out after 3 by default, so raise the limit first:

```
export TPM2TOOLS_TCTI="swtpm:path=/tmp/swtpm/sock"
tpm2_dictionarylockout -c && tpm2_dictionarylockout -s -n 32 -t 1 -l 1
```

`scripts/test-gnome-prompter.sh` tests the GNOME system prompter client against gcr-prompter on a private X server (Xvfb) and session bus; no dialog appears on your desktop.
