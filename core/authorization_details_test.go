package core

import (
	"encoding/json"
	"testing"
)

// TestAuthorizationDetail_MarshalJSON verifies that common fields and extension
// fields are flattened into a single top-level JSON object, as required by
// RFC 9396 §2.
//
// See: https://www.rfc-editor.org/rfc/rfc9396#section-2
func TestAuthorizationDetail_MarshalJSON(t *testing.T) {
	ad := AuthorizationDetail{
		Type:      "payment_initiation",
		Locations: []string{"https://bank.example.com/payments"},
		Actions:   []string{"initiate"},
		Extra: map[string]any{
			"instructedAmount": map[string]any{
				"currency": "EUR",
				"amount":   "45.00",
			},
			"creditorName": "Merchant A",
		},
	}

	data, err := json.Marshal(ad)
	if err != nil {
		t.Fatalf("MarshalJSON failed: %v", err)
	}

	// Parse back as raw map to verify flat structure
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("Unmarshal raw map failed: %v", err)
	}

	if m["type"] != "payment_initiation" {
		t.Errorf("type = %v, want payment_initiation", m["type"])
	}
	if m["creditorName"] != "Merchant A" {
		t.Errorf("creditorName = %v, want Merchant A", m["creditorName"])
	}
	// instructedAmount should be at top level, not nested under "extra"
	if _, ok := m["extra"]; ok {
		t.Error("extensions should be flattened, not nested under 'extra'")
	}
	if _, ok := m["instructedAmount"]; !ok {
		t.Error("instructedAmount extension missing from top level")
	}
}

// TestAuthorizationDetail_UnmarshalJSON verifies round-trip marshal/unmarshal
// preserves both common and extension fields.
//
// See: https://www.rfc-editor.org/rfc/rfc9396#section-2
func TestAuthorizationDetail_UnmarshalJSON(t *testing.T) {
	input := `{
		"type": "account_information",
		"actions": ["list_accounts", "read_balances"],
		"locations": ["https://bank.example.com/api"],
		"datatypes": ["balances", "transactions"],
		"identifier": "acct-123",
		"privileges": ["admin"],
		"currency": "USD",
		"maxAmount": 1000
	}`

	var ad AuthorizationDetail
	if err := json.Unmarshal([]byte(input), &ad); err != nil {
		t.Fatalf("UnmarshalJSON failed: %v", err)
	}

	if ad.Type != "account_information" {
		t.Errorf("Type = %q, want account_information", ad.Type)
	}
	if len(ad.Actions) != 2 {
		t.Errorf("Actions length = %d, want 2", len(ad.Actions))
	}
	if len(ad.Locations) != 1 {
		t.Errorf("Locations length = %d, want 1", len(ad.Locations))
	}
	if len(ad.DataTypes) != 2 {
		t.Errorf("DataTypes length = %d, want 2", len(ad.DataTypes))
	}
	if ad.Identifier != "acct-123" {
		t.Errorf("Identifier = %q, want acct-123", ad.Identifier)
	}
	if len(ad.Privileges) != 1 || ad.Privileges[0] != "admin" {
		t.Errorf("Privileges = %v, want [admin]", ad.Privileges)
	}
	// Extensions
	if ad.Extra["currency"] != "USD" {
		t.Errorf("Extra[currency] = %v, want USD", ad.Extra["currency"])
	}
	if ad.Extra["maxAmount"] != float64(1000) {
		t.Errorf("Extra[maxAmount] = %v, want 1000", ad.Extra["maxAmount"])
	}

	// Round-trip
	data, err := json.Marshal(ad)
	if err != nil {
		t.Fatalf("MarshalJSON round-trip failed: %v", err)
	}
	var ad2 AuthorizationDetail
	if err := json.Unmarshal(data, &ad2); err != nil {
		t.Fatalf("UnmarshalJSON round-trip failed: %v", err)
	}
	if ad2.Type != ad.Type {
		t.Errorf("Round-trip Type mismatch: %q != %q", ad2.Type, ad.Type)
	}
	if ad2.Extra["currency"] != ad.Extra["currency"] {
		t.Errorf("Round-trip currency mismatch")
	}
}

// TestAuthorizationDetail_Validate_MissingType verifies that an empty type
// field produces the invalid_authorization_details error.
//
// See: https://www.rfc-editor.org/rfc/rfc9396#section-2
func TestAuthorizationDetail_Validate_MissingType(t *testing.T) {
	ad := AuthorizationDetail{
		Actions: []string{"read"},
	}
	err := ad.Validate()
	if err == nil {
		t.Fatal("Validate should fail for empty type")
	}
	if err.Error() != "invalid_authorization_details: type field is required" {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestAuthorizationDetail_Validate_Valid verifies that a properly formed
// AuthorizationDetail passes validation.
//
// See: https://www.rfc-editor.org/rfc/rfc9396#section-2
func TestAuthorizationDetail_Validate_Valid(t *testing.T) {
	ad := AuthorizationDetail{
		Type:    "payment_initiation",
		Actions: []string{"initiate"},
	}
	if err := ad.Validate(); err != nil {
		t.Errorf("Validate should pass: %v", err)
	}
}

// TestValidateAll verifies batch validation of authorization details slices.
//
// See: https://www.rfc-editor.org/rfc/rfc9396#section-2
func TestValidateAll(t *testing.T) {
	// nil slice is valid
	if err := ValidateAll(nil); err != nil {
		t.Errorf("ValidateAll(nil) should pass: %v", err)
	}

	// empty slice is valid
	if err := ValidateAll([]AuthorizationDetail{}); err != nil {
		t.Errorf("ValidateAll([]) should pass: %v", err)
	}

	// all valid
	details := []AuthorizationDetail{
		{Type: "a"},
		{Type: "b"},
	}
	if err := ValidateAll(details); err != nil {
		t.Errorf("ValidateAll with valid details should pass: %v", err)
	}

	// one invalid
	details = append(details, AuthorizationDetail{Actions: []string{"read"}})
	if err := ValidateAll(details); err == nil {
		t.Error("ValidateAll should fail when one detail has no type")
	}
}

// TestFilterByType verifies filtering authorization details by type name.
//
// See: https://www.rfc-editor.org/rfc/rfc9396#section-2
func TestFilterByType(t *testing.T) {
	details := []AuthorizationDetail{
		{Type: "payment_initiation", Actions: []string{"initiate"}},
		{Type: "account_information", Actions: []string{"read"}},
		{Type: "payment_initiation", Actions: []string{"cancel"}},
	}

	payments := FilterByType(details, "payment_initiation")
	if len(payments) != 2 {
		t.Errorf("FilterByType(payment_initiation) = %d results, want 2", len(payments))
	}

	accounts := FilterByType(details, "account_information")
	if len(accounts) != 1 {
		t.Errorf("FilterByType(account_information) = %d results, want 1", len(accounts))
	}

	unknown := FilterByType(details, "unknown")
	if unknown != nil {
		t.Errorf("FilterByType(unknown) = %v, want nil", unknown)
	}

	// nil input
	if FilterByType(nil, "payment") != nil {
		t.Error("FilterByType(nil) should return nil")
	}
}

// TestAuthorizationDetail_NoExtensions verifies marshal/unmarshal with only
// common fields (no extensions).
//
// See: https://www.rfc-editor.org/rfc/rfc9396#section-2
func TestAuthorizationDetail_NoExtensions(t *testing.T) {
	ad := AuthorizationDetail{
		Type:    "openid_credential",
		Actions: []string{"issue"},
	}

	data, err := json.Marshal(ad)
	if err != nil {
		t.Fatalf("MarshalJSON failed: %v", err)
	}

	var ad2 AuthorizationDetail
	if err := json.Unmarshal(data, &ad2); err != nil {
		t.Fatalf("UnmarshalJSON failed: %v", err)
	}

	if ad2.Type != "openid_credential" {
		t.Errorf("Type = %q, want openid_credential", ad2.Type)
	}
	if ad2.Extra != nil {
		t.Errorf("Extra should be nil for no-extension object, got %v", ad2.Extra)
	}
}
