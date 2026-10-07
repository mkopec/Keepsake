#!/bin/sh
# Runs the system prompter integration test on a private X server and
# session bus, so no dialogs appear on the desktop. Needs Xvfb, xdotool and
# gcr (gcr-prompter).
set -e
cd "$(dirname "$0")/.."
export TPMFIDO_PROMPTER_TEST=1
exec xvfb-run -a -s "-screen 0 1024x768x24" \
	dbus-run-session -- go test -count=1 -v -run TestSystemPrompter ./gnome "$@"
