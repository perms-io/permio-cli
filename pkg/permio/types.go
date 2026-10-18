package permio

import (
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"

	permissionsv1 "github.com/PrivateJAR/permio-go/proto/permissions/v1"
)

// Permission is a named action, e.g. "document.read".
type Permission struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// Role is a named set of permissions. Roles are addressed by ID.
type Role struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
}

// RoleRef identifies a role in a grant.
type RoleRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Group is a named set of principals. Grants to Group.PrincipalID
// ("group:<name>") apply to every member.
type Group struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	PrincipalID string     `json:"principal_id"`
	CreatedAt   *time.Time `json:"created_at,omitempty"`
	UpdatedAt   *time.Time `json:"updated_at,omitempty"`
}

// Grant is the roles and permissions granted to one principal on exactly one
// resource URI.
type Grant struct {
	Principal   string    `json:"principal"`
	Resource    string    `json:"resource"`
	Roles       []RoleRef `json:"roles"`
	Permissions []string  `json:"permissions"`
}

// CheckResult is the result of Check.
type CheckResult struct {
	// Allowed is true when the principal holds every permission on every resource.
	Allowed bool `json:"allowed"`
	// Missing lists what is missing per resource. Empty when allowed.
	Missing []MissingPermission `json:"missing"`
}

// BatchResult is one resource's result from BatchCheck.
type BatchResult struct {
	Resource string   `json:"resource"`
	Allowed  bool     `json:"allowed"`
	Missing  []string `json:"missing"`
}

func permissionFromPB(p *permissionsv1.Permission) Permission {
	return Permission{Name: p.GetName(), Description: p.GetDescription()}
}

func roleFromPB(r *permissionsv1.Role) Role {
	out := Role{ID: r.GetId(), Name: r.GetName(), Description: r.GetDescription(), Permissions: []string{}}
	for _, p := range r.GetPermissions() {
		out.Permissions = append(out.Permissions, p.GetName())
	}
	sort.Strings(out.Permissions)
	return out
}

func groupFromPB(g *permissionsv1.Group) Group {
	out := Group{Name: g.GetName(), Description: g.GetDescription(), PrincipalID: g.GetPrincipalId()}
	if out.PrincipalID == "" {
		out.PrincipalID = GroupPrincipal(out.Name)
	}
	if g.GetCreatedAt() != nil {
		t := g.GetCreatedAt().AsTime()
		out.CreatedAt = &t
	}
	if g.GetUpdatedAt() != nil {
		t := g.GetUpdatedAt().AsTime()
		out.UpdatedAt = &t
	}
	return out
}

// GroupPrefix starts the principal ID of every group.
const GroupPrefix = "group:"

// GroupPrincipal returns the principal ID of the group with this slug.
func GroupPrincipal(slug string) string { return GroupPrefix + slug }

// MaxResourceURILength is the longest resource URI the API accepts, in bytes.
const MaxResourceURILength = 2048

// ValidateResourceURI checks the basic shape the API accepts: a leading "/",
// no empty segments, no whitespace or control characters, no regex
// metacharacters in segments, at most 2048 bytes.
func ValidateResourceURI(uri string) error {
	fail := func(why string) error { return invalid("invalid resource URI %q: %s", uri, why) }
	if uri == "" {
		return fail("it is empty")
	}
	if !strings.HasPrefix(uri, "/") {
		return fail(`it must start with "/", e.g. /documents/42`)
	}
	if len(uri) > MaxResourceURILength {
		return fail(fmt.Sprintf("it is longer than %d bytes", MaxResourceURILength))
	}
	for _, r := range uri {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return fail("it contains whitespace or control characters")
		}
		if strings.ContainsRune(`()[]{}*+?|^$\`, r) {
			return fail(fmt.Sprintf("segments may not contain %q", r))
		}
	}
	for _, seg := range strings.Split(uri[1:], "/") {
		if seg == "" {
			return fail("it contains an empty segment (no // or trailing /)")
		}
	}
	return nil
}

func uniq(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
