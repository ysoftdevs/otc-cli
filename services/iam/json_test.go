package iam

import (
	"strings"
	"testing"
)

func TestJSONDuplicateMembersAreRejectedWithoutValues(t *testing.T) {
	for _, input := range []string{
		`{"keys":[{"d":"private-fixture"}],"keys":[]}`,
		`{"policy":{"allow":true,"allow":false}}`,
		`{"keys":[{"kid":"a","kid":"b"}]}`,
		`{"a":1,"\u0061":2}`,
	} {
		if err := validateJSONDocument([]byte(input)); err == nil || strings.Contains(err.Error(), "private-fixture") {
			t.Errorf("validation error = %v; want value-free duplicate rejection", err)
		}
	}
}

func TestJSONValidationPreservesIndependentObjectKeys(t *testing.T) {
	for _, input := range []string{`{"keys":[{"kid":"a"},{"kid":"b"}]}`, `[]`, `null`, `{"large":9007199254740993}`} {
		if err := validateJSONDocument([]byte(input)); err != nil {
			t.Errorf("valid JSON rejected: %v", err)
		}
	}
}

func TestJSONValidationRejectsDeepMalformedAndTrailingData(t *testing.T) {
	for _, input := range []string{"", "{", "[}", "{} []", "true garbage", strings.Repeat("[", 130) + "0" + strings.Repeat("]", 130)} {
		if err := validateJSONDocument([]byte(input)); err == nil {
			t.Error("invalid/deep JSON accepted")
		}
	}
}
