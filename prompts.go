package main

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/psanford/tpm-fido/pinentry"
)

// The texts of the confirmation dialogs, written for the GNOME Shell system
// prompt that pinentry-gnome3 shows. Following the GNOME HIG, the heading
// asks the question in header capitalization, the body explains the
// consequence in a sentence, and the confirming button names the action.

func signInPrompt(site string) pinentry.Prompt {
	if site == "" {
		return pinentry.Prompt{
			Heading: "Sign In with Security Key?",
			Body:    "A website wants to confirm it’s you using the security key in this computer.",
			OK:      "Sign In",
		}
	}
	return pinentry.Prompt{
		Heading: fmt.Sprintf("Sign In to %s?", site),
		Body:    fmt.Sprintf("%s wants to confirm it’s you using the security key in this computer.", site),
		OK:      "Sign In",
	}
}

func registerPrompt(site, user string) pinentry.Prompt {
	if site == "" {
		return pinentry.Prompt{
			Heading: "Register Security Key?",
			Body:    "A website wants to register the security key in this computer, so you can use it to sign in.",
			OK:      "Register",
		}
	}
	as := ""
	if user != "" {
		as = fmt.Sprintf(" as “%s”", user)
	}
	return pinentry.Prompt{
		Heading: fmt.Sprintf("Register Security Key with %s?", site),
		Body:    fmt.Sprintf("You will be able to sign in to %s%s using the security key in this computer.", site, as),
		OK:      "Register",
	}
}

func passkeyPrompt(site, user string) pinentry.Prompt {
	as := ""
	if user != "" {
		as = fmt.Sprintf(" as “%s”", user)
	}
	return pinentry.Prompt{
		Heading: fmt.Sprintf("Create Passkey for %s?", site),
		Body:    fmt.Sprintf("The passkey is stored in this computer’s security chip. You will be able to sign in to %s%s without typing a username.", site, as),
		OK:      "Create Passkey",
	}
}

func alreadyRegisteredPrompt(site string) pinentry.Prompt {
	return pinentry.Prompt{
		Heading: "Security Key Already Registered",
		Body:    fmt.Sprintf("The security key in this computer is already registered with %s.", site),
		OK:      "Continue",
	}
}

func selectPrompt() pinentry.Prompt {
	return pinentry.Prompt{
		Heading: "Use This Security Key?",
		Body:    "A website or app wants to use the security key in this computer.",
		OK:      "Use Security Key",
	}
}

func resetPrompt() pinentry.Prompt {
	return pinentry.Prompt{
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
