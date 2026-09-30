package iam

// signing_key is a JSON string inside the outer configuration document.
// Generic recursive redaction cannot inspect that second encoding. Keep valid
// public JWKS reviewable, but suppress the entire value if parsing, ambiguity,
// private-material checks, or supported public-key validation fail.
func redactMutationSigningKey(value any) any {
	if _, err := parseSigningKeys(value); err != nil {
		return "<redacted: invalid or private signing_key>"
	}
	return value
}
