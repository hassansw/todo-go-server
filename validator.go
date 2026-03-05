package validator

import (
	"net/mail"
	"strings"
	"unicode/utf8"
)

// ValidEmail checks RFC 5322 compliance.
func ValidEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	if err != nil {
		return false
	}
	// Additional: must contain a dot in the domain
	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 || !strings.Contains(parts[1], ".") {
		return false
	}
	return true
}

// ValidPassword enforces minimum security requirements.
func ValidPassword(pw string) (bool, string) {
	if utf8.RuneCountInString(pw) < 8 {
		return false, "Password must be at least 8 characters"
	}
	if utf8.RuneCountInString(pw) > 128 {
		return false, "Password must be at most 128 characters"
	}

	var hasUpper, hasLower, hasDigit bool
	for _, r := range pw {
		switch {
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= '0' && r <= '9':
			hasDigit = true
		}
	}
	if !hasUpper || !hasLower || !hasDigit {
		return false, "Password must contain uppercase, lowercase, and a digit"
	}
	return true, ""
}

// ValidPriority checks the todo priority enum.
func ValidPriority(p string) bool {
	return p == "low" || p == "medium" || p == "high"
}

// SanitiseString trims whitespace and limits length.
func SanitiseString(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) > maxLen {
		runes := []rune(s)
		s = string(runes[:maxLen])
	}
	return s
}

// ValidName checks name is not empty and not too long.
func ValidName(name string) (bool, string) {
	if name == "" {
		return false, "Name is required"
	}
	if utf8.RuneCountInString(name) > 100 {
		return false, "Name must be at most 100 characters"
	}
	return true, ""
}
