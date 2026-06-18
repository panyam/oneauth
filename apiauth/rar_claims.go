package apiauth

import (
	"github.com/panyam/oneauth/core"
)

// standardADFields are the RFC 9396 §2 common field names used when
// parsing authorization_details from JWT claims to separate known
// fields from extensions.
var standardADFields = map[string]bool{
	"type": true, "locations": true, "actions": true,
	"datatypes": true, "identifier": true, "privileges": true,
}

// parseAuthorizationDetailsFromClaims converts raw JWT claim data
// ([]any of map[string]any) into typed AuthorizationDetail structs.
// Unknown fields land in Extra so RFC 9396 extensions round-trip.
func parseAuthorizationDetailsFromClaims(raw []any) []core.AuthorizationDetail {
	var result []core.AuthorizationDetail
	for _, item := range raw {
		adMap, ok := item.(map[string]any)
		if !ok {
			continue
		}
		ad := core.AuthorizationDetail{
			Type:       stringFromMap(adMap, "type"),
			Identifier: stringFromMap(adMap, "identifier"),
			Locations:  toStringSlice(anySliceFromMap(adMap, "locations")),
			Actions:    toStringSlice(anySliceFromMap(adMap, "actions")),
			DataTypes:  toStringSlice(anySliceFromMap(adMap, "datatypes")),
			Privileges: toStringSlice(anySliceFromMap(adMap, "privileges")),
		}
		for k, v := range adMap {
			if !standardADFields[k] {
				if ad.Extra == nil {
					ad.Extra = make(map[string]any)
				}
				ad.Extra[k] = v
			}
		}
		result = append(result, ad)
	}
	return result
}

func stringFromMap(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func anySliceFromMap(m map[string]any, key string) []any {
	if v, ok := m[key].([]any); ok {
		return v
	}
	return nil
}

func toStringSlice(raw []any) []string {
	if len(raw) == 0 {
		return nil
	}
	result := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			result = append(result, s)
		}
	}
	return result
}
