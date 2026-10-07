package main

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/psanford/tpm-fido/ui"
)

// The texts of the confirmation dialogs, written for the GNOME Shell system
// prompt that pinentry-gnome3 shows. Following the GNOME HIG, the heading
// asks the question in header capitalization, the body explains the
// consequence in a sentence, and the confirming button names the action.

func signInPrompt(site string) ui.Prompt {
	if site == "" {
		return ui.Prompt{
			Heading: "Sign In with Security Key?",
			Body:    "A website wants to confirm it’s you using the security key in this computer.",
			OK:      "Sign In",
		}
	}
	return ui.Prompt{
		Heading: fmt.Sprintf("Sign In to %s?", site),
		Body:    fmt.Sprintf("%s wants to confirm it’s you using the security key in this computer.", site),
		OK:      "Sign In",
	}
}

func registerPrompt(site, user string) ui.Prompt {
	if site == "" {
		return ui.Prompt{
			Heading: "Register Security Key?",
			Body:    "A website wants to register the security key in this computer, so you can use it to sign in.",
			OK:      "Register",
		}
	}
	as := ""
	if user != "" {
		as = fmt.Sprintf(" as “%s”", user)
	}
	return ui.Prompt{
		Heading: fmt.Sprintf("Register Security Key with %s?", site),
		Body:    fmt.Sprintf("You will be able to sign in to %s%s using the security key in this computer.", site, as),
		OK:      "Register",
	}
}

func passkeyPrompt(site, user string) ui.Prompt {
	as := ""
	if user != "" {
		as = fmt.Sprintf(" as “%s”", user)
	}
	return ui.Prompt{
		Heading: fmt.Sprintf("Create Passkey for %s?", site),
		Body:    fmt.Sprintf("The passkey is stored in this computer’s security chip. You will be able to sign in to %s%s without typing a username.", site, as),
		OK:      "Create Passkey",
	}
}

func alreadyRegisteredPrompt(site string) ui.Prompt {
	return ui.Prompt{
		Heading: "Security Key Already Registered",
		Body:    fmt.Sprintf("The security key in this computer is already registered with %s.", site),
		OK:      "Continue",
	}
}

func selectPrompt() ui.Prompt {
	return ui.Prompt{
		Heading: "Use This Security Key?",
		Body:    "A website or app wants to use the security key in this computer.",
		OK:      "Use Security Key",
	}
}

// sshPINPrompt asks for the PIN on behalf of an SSH agent. message is the
// agent's prompt, e.g. "Enter PIN and confirm user presence for ECDSA-SK key
// SHA256:...: ". Entering the PIN also confirms the signature, so the
// confirming button signs in.
func sshPINPrompt(message string) ui.PasswordPrompt {
	body := "Enter the PIN of the security key in this computer to sign in with SSH."
	if fp := sshKeyFingerprint(message); fp != "" {
		body = fmt.Sprintf("Enter the PIN of the security key in this computer to sign in with SSH key %s.", fp)
	}
	return ui.PasswordPrompt{Prompt: ui.Prompt{
		Heading: "Sign In with SSH Key?",
		Body:    body,
		OK:      "Sign In",
	}}
}

// sshKeyFingerprint returns the "SHA256:..." fingerprint in an ssh prompt.
func sshKeyFingerprint(message string) string {
	for _, f := range strings.Fields(message) {
		if strings.HasPrefix(f, "SHA256:") {
			return displayText(strings.TrimRight(f, ":"), 60)
		}
	}
	return ""
}

func setPINPrompt() ui.Prompt {
	return ui.Prompt{
		Heading: "Set Security Key PIN?",
		Body:    "A website or app wants to set the PIN of the security key in this computer. Websites will be able to ask for it to verify it’s you.",
		OK:      "Set PIN",
	}
}

func resetPrompt() ui.Prompt {
	return ui.Prompt{
		Heading: "Reset Security Key?",
		Body:    "All passkeys, security key registrations and the PIN will be permanently deleted. You will no longer be able to sign in with them.",
		OK:      "Reset",
	}
}

// displayText makes text sent by a website safe to show: it removes control
// characters (which could fake extra lines in the dialog) and shortens it.
func displayText(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		// format characters include bidi overrides, which can make
		// a domain read differently
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == unicode.ReplacementChar {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > max {
		s = string(r[:max]) + "…"
	}
	return s
}
