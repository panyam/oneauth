package core

import (
	"encoding/json"
	"fmt"
)

// ErrInvalidAuthorizationDetails is the OAuth error for malformed or disallowed
// authorization_details values (RFC 9396 §5.2).
var ErrInvalidAuthorizationDetails = fmt.Errorf("invalid_authorization_details")

// commonFields lists the RFC 9396 §2 common field names. These cannot appear
// as extension keys in AuthorizationDetail.Extra.
var commonFields = map[string]bool{
	"type": true, "locations": true, "actions": true,
	"datatypes": true, "identifier": true, "privileges": true,
}

// AuthorizationDetail represents a single authorization details object per
// RFC 9396 §2. Each object describes fine-grained authorization requirements
// for a specific API or resource type.
//
// The Type field is required and identifies the authorization details type.
// Common fields (Locations, Actions, DataTypes, Identifier, Privileges) are
// optional and defined by the spec. API-specific extension fields are stored
// in Extra and flattened into the top-level JSON object on marshal.
//
// See: https://www.rfc-editor.org/rfc/rfc9396#section-2
type AuthorizationDetail struct {
	// Type is the authorization details type identifier (required).
	Type string `json:"type"`

	// Locations is an array of URIs indicating where the requested
	// resource can be found.
	Locations []string `json:"locations,omitempty"`

	// Actions is an array of strings describing the operations to be
	// performed on the resource.
	Actions []string `json:"actions,omitempty"`

	// DataTypes is an array of strings describing the types of data
	// being requested.
	DataTypes []string `json:"datatypes,omitempty"`

	// Identifier is a string identifying a specific resource at the API.
	Identifier string `json:"identifier,omitempty"`

	// Privileges is an array of strings representing privilege levels.
	Privileges []string `json:"privileges,omitempty"`

	// Extra holds API-specific extension fields. These are flattened into
	// the top-level JSON object (not nested under an "extra" key).
	Extra map[string]any `json:"-"`
}

// Validate checks that the AuthorizationDetail has a non-empty Type field.
//
// See: https://www.rfc-editor.org/rfc/rfc9396#section-2
func (ad *AuthorizationDetail) Validate() error {
	if ad.Type == "" {
		return fmt.Errorf("%w: type field is required", ErrInvalidAuthorizationDetails)
	}
	return nil
}

// ValidateAll validates a slice of AuthorizationDetail values.
// Returns nil if the slice is nil or empty.
func ValidateAll(details []AuthorizationDetail) error {
	for i := range details {
		if err := details[i].Validate(); err != nil {
			return err
		}
	}
	return nil
}

// FilterByType returns the subset of details matching the given type.
// Returns nil if no matches are found.
func FilterByType(details []AuthorizationDetail, typ string) []AuthorizationDetail {
	var result []AuthorizationDetail
	for _, d := range details {
		if d.Type == typ {
			result = append(result, d)
		}
	}
	return result
}

// MarshalJSON flattens Extra fields into the top-level JSON object alongside
// the common RFC 9396 fields. This produces the flat structure required by the
// spec (e.g., {"type":"payment","amount":"45"}) rather than nesting extensions.
func (ad AuthorizationDetail) MarshalJSON() ([]byte, error) {
	// Build a map with common fields
	m := make(map[string]any)
	m["type"] = ad.Type
	if len(ad.Locations) > 0 {
		m["locations"] = ad.Locations
	}
	if len(ad.Actions) > 0 {
		m["actions"] = ad.Actions
	}
	if len(ad.DataTypes) > 0 {
		m["datatypes"] = ad.DataTypes
	}
	if ad.Identifier != "" {
		m["identifier"] = ad.Identifier
	}
	if len(ad.Privileges) > 0 {
		m["privileges"] = ad.Privileges
	}
	// Flatten extensions
	for k, v := range ad.Extra {
		if !commonFields[k] {
			m[k] = v
		}
	}
	return json.Marshal(m)
}

// UnmarshalJSON parses a flat JSON object into the common fields and Extra.
// Extension keys that collide with common field names are rejected.
func (ad *AuthorizationDetail) UnmarshalJSON(data []byte) error {
	// First pass: decode common fields via a type alias (avoids recursion)
	type Alias AuthorizationDetail
	var alias Alias
	if err := json.Unmarshal(data, &alias); err != nil {
		return err
	}
	*ad = AuthorizationDetail(alias)

	// Second pass: decode all keys to find extensions
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	// Collect extension fields
	ad.Extra = nil
	for k, v := range raw {
		if commonFields[k] {
			continue
		}
		if ad.Extra == nil {
			ad.Extra = make(map[string]any)
		}
		var val any
		if err := json.Unmarshal(v, &val); err != nil {
			return fmt.Errorf("failed to unmarshal extension field %q: %w", k, err)
		}
		ad.Extra[k] = val
	}
	return nil
}
