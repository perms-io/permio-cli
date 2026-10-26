package permio

import (
	"reflect"
	"testing"
)

func TestAccessScopes(t *testing.T) {
	a := &AccessScopes{Under: "/docs", Scopes: []AccessScope{
		{URI: "/docs/1", Kind: ScopeSubtree},
		{URI: "/docs/1/sub", Kind: ScopeSubtree},
		{URI: "/docs/_/public", Kind: ScopePattern},
		{URI: "/docs/x", Kind: ScopeUnknown},
	}}
	cases := map[string]bool{
		"/docs/1":          true,
		"/docs/1/a/b":      true,
		"/docs/12":         false, // segment-wise, not string prefix
		"/docs/7/public":   true,
		"/docs/7/public/x": true,
		"/docs/7":          false,
		"/docs/x":          false, // unknown kinds never match
		"docs/1":           false,
		"/docs//1":         false,
	}
	for uri, want := range cases {
		if got := a.Allows(uri); got != want {
			t.Errorf("Allows(%q) = %v, want %v", uri, got, want)
		}
	}
	if got := a.Prefixes(); !reflect.DeepEqual(got, []string{"/docs/1"}) {
		t.Errorf("Prefixes = %v", got)
	}
	if got := a.Patterns(); !reflect.DeepEqual(got, []string{"/docs/_/public"}) {
		t.Errorf("Patterns = %v", got)
	}
}

func TestValidateResourceURI(t *testing.T) {
	for _, ok := range []string{"/a", "/a/b/c", "/tenants/_/docs", "/a%2Fb"} {
		if err := ValidateResourceURI(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "a", "/a/", "//a", "/a b", "/a(1)", "/a*"} {
		if err := ValidateResourceURI(bad); err == nil {
			t.Errorf("%q: expected error", bad)
		}
	}
}

func TestFindRole(t *testing.T) {
	roles := []Role{{ID: "r1", Name: "editor"}, {ID: "r2", Name: "dup"}, {ID: "r3", Name: "dup"}, {ID: "editor2", Name: "r1"}}
	if r, _ := FindRole(roles, "r1"); r.ID != "r1" {
		t.Errorf("ID should win over name: %+v", r)
	}
	if r, _ := FindRole(roles, "editor"); r.ID != "r1" {
		t.Errorf("by name: %+v", r)
	}
	if _, err := FindRole(roles, "dup"); KindOf(err) != KindInvalid {
		t.Errorf("ambiguous: %v", err)
	}
	if _, err := FindRole(roles, "nope"); !IsNotFound(err) {
		t.Errorf("missing: %v", err)
	}
}

func TestIdempotentMethods(t *testing.T) {
	if !IsIdempotent("/permio.permissions.v1.PermissionsService/Check") {
		t.Error("Check should be retried")
	}
	if IsIdempotent("/permio.permissions.v1.PermissionsService/GrantUserPermissionsAndRolesOnResource") {
		t.Error("writes must not be retried")
	}
}
