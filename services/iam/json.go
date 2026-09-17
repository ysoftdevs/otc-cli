package iam

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// Duplicate object members have parser-dependent meanings. Reject them before
// interpreting an authorization document or displaying its original JSON text.
// Error messages intentionally contain no field names or document values.
func validateJSONDocument(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := validateJSONValue(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return fmt.Errorf("IAM response must contain exactly one JSON value")
	}
	return nil
}

func validateJSONValue(decoder *json.Decoder, depth int) error {
	if depth > 128 {
		return fmt.Errorf("IAM JSON nesting exceeds 128 levels")
	}
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("IAM response contains invalid JSON")
	}
	delimiter, nested := token.(json.Delim)
	if !nested {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]bool)
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("IAM response contains an invalid JSON object")
			}
			name, ok := key.(string)
			if !ok {
				return fmt.Errorf("IAM response contains an invalid JSON object key")
			}
			if seen[name] {
				return fmt.Errorf("IAM response contains duplicate JSON object members")
			}
			seen[name] = true
			if err := validateJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := validateJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("IAM response contains an unexpected JSON delimiter")
	}
	end, err := decoder.Token()
	if err != nil || (delimiter == '{' && end != json.Delim('}')) || (delimiter == '[' && end != json.Delim(']')) {
		return fmt.Errorf("IAM response contains an unclosed JSON structure")
	}
	return nil
}
