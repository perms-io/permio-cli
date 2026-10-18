package permio

import (
	"context"
	"sort"
	"strings"

	paginationv1 "github.com/PrivateJAR/permio-go/proto/pagination/v1"
	pb "github.com/PrivateJAR/permio-go/proto/permissions/v1"
)

// WildcardSegment is the "_" segment: in a stored grant URI or a pattern scope
// it matches exactly one segment.
const WildcardSegment = "_"

// Scope kinds.
const (
	ScopeSubtree = "subtree"
	ScopePattern = "pattern"
	ScopeExact   = "exact"
	ScopeUnknown = "unknown"
)

// AccessScope is one place where a principal holds a permission.
type AccessScope struct {
	// URI is a resource URI (subtree, exact) or a URI pattern with "_" segments (pattern).
	URI string `json:"uri"`
	// Kind is "subtree" (the URI and everything below), "pattern" (URIs whose
	// leading segments match, "_" matching one segment, and everything below),
	// "exact" (reserved by the API) or "unknown".
	Kind string `json:"kind"`
}

// AccessScopes answers "where may this principal use this permission under Under?".
type AccessScopes struct {
	Under string `json:"under"`
	// CoversAll is true when the principal holds the permission on Under itself,
	// and so on everything below it.
	CoversAll bool          `json:"covers_all"`
	Scopes    []AccessScope `json:"scopes"`
}

func scopeKind(k pb.AccessScopeKind) string {
	switch k {
	case pb.AccessScopeKind_ACCESS_SCOPE_KIND_SUBTREE:
		return ScopeSubtree
	case pb.AccessScopeKind_ACCESS_SCOPE_KIND_PATTERN:
		return ScopePattern
	case pb.AccessScopeKind_ACCESS_SCOPE_KIND_EXACT:
		return ScopeExact
	default:
		return ScopeUnknown
	}
}

// segments splits "/a/b" into ["a","b"]; nil for malformed URIs.
func segments(uri string) []string {
	if len(uri) < 2 || !strings.HasPrefix(uri, "/") {
		return nil
	}
	parts := strings.Split(uri[1:], "/")
	for _, p := range parts {
		if p == "" {
			return nil
		}
	}
	return parts
}

func (s AccessScope) matches(target []string) bool {
	own := segments(s.URI)
	if own == nil || len(own) > len(target) {
		return false
	}
	switch s.Kind {
	case ScopeExact:
		if len(own) != len(target) {
			return false
		}
		fallthrough
	case ScopeSubtree:
		// Segment by segment, so /a/b covers /a/b/c but not /a/bc. "_" is literal here.
		for i := range own {
			if own[i] != target[i] {
				return false
			}
		}
		return true
	case ScopePattern:
		for i := range own {
			if own[i] != WildcardSegment && own[i] != target[i] {
				return false
			}
		}
		return true
	default:
		return false
	}
}

// Allows reports whether the scopes cover uri. A URI outside Under was not
// asked about, so false for it means "unknown", not "denied".
func (a *AccessScopes) Allows(uri string) bool {
	target := segments(uri)
	if target == nil {
		return false
	}
	for _, s := range a.Scopes {
		if s.matches(target) {
			return true
		}
	}
	return false
}

// Prefixes returns the subtree scopes' URIs, dropping any already covered by a
// shorter one. A prefix p stands for p and everything below it: match
// `path = p OR path LIKE p + "/%"`.
func (a *AccessScopes) Prefixes() []string {
	var subtrees []string
	for _, s := range a.Scopes {
		if s.Kind == ScopeSubtree {
			subtrees = append(subtrees, s.URI)
		}
	}
	subtrees = uniq(subtrees)
	out := []string{}
	for _, p := range subtrees {
		covered := false
		for _, q := range subtrees {
			if strings.HasPrefix(p, q+"/") {
				covered = true
				break
			}
		}
		if !covered {
			out = append(out, p)
		}
	}
	return out
}

// Patterns returns the pattern scopes' URIs (with "_" segments).
func (a *AccessScopes) Patterns() []string {
	out := []string{}
	for _, s := range a.Scopes {
		if s.Kind == ScopePattern {
			out = append(out, s.URI)
		}
	}
	return out
}

// ListAccess answers "where may principal use permission at or below under?",
// following every page. Access through roles and groups counts.
func (c *Client) ListAccess(ctx context.Context, principal, permission, under string) (*AccessScopes, error) {
	if principal == "" || permission == "" {
		return nil, invalid("principal and permission are required")
	}
	if err := ValidateResourceURI(under); err != nil {
		return nil, err
	}
	out := &AccessScopes{Under: under, Scopes: []AccessScope{}}
	err := paginate(ctx, func(p *paginationv1.PaginationRequest) (string, error) {
		res, err := c.Raw.ListAccess(ctx, &pb.ListAccessRequest{ProjectName: c.Project, PrincipalId: principal, Permission: permission, UnderUri: under, Pagination: p})
		if err != nil {
			return "", err
		}
		if res.GetCoversAll() {
			out.CoversAll = true
		}
		for _, s := range res.GetScopes() {
			out.Scopes = append(out.Scopes, AccessScope{URI: s.GetUri(), Kind: scopeKind(s.GetScope())})
		}
		return res.GetPagination().GetNextCursor(), nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// AccessVia is one grant (or one role within a grant) that gives access.
type AccessVia struct {
	// Resource is the URI the grant was made on.
	Resource string `json:"resource"`
	// Inherited is true unless the grant was made on exactly the resource.
	Inherited bool `json:"inherited"`
	// Match is "exact", "ancestor", "wildcard" or "unknown".
	Match string `json:"match"`
	// Source is "role" or "direct".
	Source   string `json:"source"`
	RoleID   string `json:"role_id,omitempty"`
	RoleName string `json:"role_name,omitempty"`
}

// AccessEntry is one principal with access to a resource.
type AccessEntry struct {
	Principal string `json:"principal"`
	IsGroup   bool   `json:"is_group"`
	// ViaGroup is the group slug through which Principal has access, for
	// entries added by expand_groups; empty for the principal's own grants.
	ViaGroup string      `json:"via_group"`
	Via      []AccessVia `json:"via"`
}

func matchName(m pb.AccessGrantMatch) string {
	switch m {
	case pb.AccessGrantMatch_ACCESS_GRANT_MATCH_EXACT:
		return "exact"
	case pb.AccessGrantMatch_ACCESS_GRANT_MATCH_ANCESTOR:
		return "ancestor"
	case pb.AccessGrantMatch_ACCESS_GRANT_MATCH_WILDCARD:
		return "wildcard"
	default:
		return "unknown"
	}
}

// WhoHasAccess lists the principals with a grant on resource, an ancestor of
// it, or a "_" wildcard URI matching it. With permission set only grants that
// confer it count. With expandGroups, members of listed groups are listed too.
func (c *Client) WhoHasAccess(ctx context.Context, resource, permission string, expandGroups bool) ([]AccessEntry, error) {
	if err := ValidateResourceURI(resource); err != nil {
		return nil, err
	}
	out := []AccessEntry{}
	err := paginate(ctx, func(p *paginationv1.PaginationRequest) (string, error) {
		res, err := c.Raw.ListPrincipalsWithAccess(ctx, &pb.ListPrincipalsWithAccessRequest{
			ProjectName: c.Project, ResourceUri: resource, Permission: optString(permission), ExpandGroups: expandGroups, Pagination: p,
		})
		if err != nil {
			return "", err
		}
		for _, pa := range res.GetPrincipals() {
			e := AccessEntry{Principal: pa.GetPrincipalId(), IsGroup: pa.GetIsGroup(), ViaGroup: pa.GetViaGroup(), Via: []AccessVia{}}
			for _, g := range pa.GetVia() {
				v := AccessVia{Resource: g.GetResourceUri(), Inherited: g.GetInherited(), Match: matchName(g.GetMatch())}
				switch src := g.GetSource().(type) {
				case *pb.AccessGrant_Role:
					v.Source, v.RoleID, v.RoleName = "role", src.Role.GetId(), src.Role.GetName()
				case *pb.AccessGrant_Direct:
					v.Source = "direct"
				default:
					v.Source = "unknown"
				}
				e.Via = append(e.Via, v)
			}
			out = append(out, e)
		}
		return res.GetPagination().GetNextCursor(), nil
	})
	if err != nil {
		return nil, err
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Principal != out[j].Principal {
			return out[i].Principal < out[j].Principal
		}
		return out[i].ViaGroup < out[j].ViaGroup
	})
	return out, nil
}
