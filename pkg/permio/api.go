package permio

import (
	"context"
	"fmt"
	"sort"

	paginationv1 "github.com/PrivateJAR/permio-go/proto/pagination/v1"
	pb "github.com/PrivateJAR/permio-go/proto/permissions/v1"
	"google.golang.org/protobuf/proto"
)

// PageSize is the page size used when following pagination (the API maximum).
const PageSize = 100

// MaxBatch is the most resources or permissions one Check or BatchCheck accepts.
const MaxBatch = 100

// paginate calls fetch until the API returns an empty (or repeated) cursor.
func paginate(ctx context.Context, fetch func(p *paginationv1.PaginationRequest) (string, error)) error {
	var cursor *string
	seen := map[string]bool{}
	for {
		if err := ctx.Err(); err != nil {
			return toError(err)
		}
		next, err := fetch(&paginationv1.PaginationRequest{Limit: proto.Int32(PageSize), Cursor: cursor})
		if err != nil {
			return err
		}
		if next == "" || seen[next] {
			return nil
		}
		seen[next] = true
		cursor = proto.String(next)
	}
}

func optString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// Check reports whether principal holds every permission on every resource.
// A denial is a normal result, not an error.
func (c *Client) Check(ctx context.Context, principal string, resources, permissions []string) (*CheckResult, error) {
	if principal == "" {
		return nil, invalid("principal is required")
	}
	resources, permissions = uniq(resources), uniq(permissions)
	if len(resources) == 0 || len(permissions) == 0 {
		return nil, invalid("at least one resource and one permission are required")
	}
	if len(resources) > MaxBatch || len(permissions) > MaxBatch {
		return nil, invalid("at most %d resources and %d permissions per check", MaxBatch, MaxBatch)
	}
	for _, r := range resources {
		if err := ValidateResourceURI(r); err != nil {
			return nil, err
		}
	}
	res, err := c.Raw.Check(ctx, &pb.CheckPermissionRequest{
		ProjectName: c.Project, PrincipalId: principal, ResourceUris: resources, Permissions: permissions,
	})
	if err != nil {
		return nil, err
	}
	out := &CheckResult{Allowed: res.GetPassed(), Missing: []MissingPermission{}}
	for _, m := range res.GetMissingPermissions() {
		if len(m.GetMissingPermissions()) == 0 {
			continue
		}
		out.Missing = append(out.Missing, MissingPermission{Resource: m.GetResourceUri(), Permissions: m.GetMissingPermissions()})
	}
	return out, nil
}

// BatchCheck checks each resource separately, in request order. More than 100
// resources are split into several calls.
func (c *Client) BatchCheck(ctx context.Context, principal string, resources, permissions []string) ([]BatchResult, error) {
	if principal == "" {
		return nil, invalid("principal is required")
	}
	resources, permissions = uniq(resources), uniq(permissions)
	if len(resources) == 0 || len(permissions) == 0 {
		return nil, invalid("at least one resource and one permission are required")
	}
	if len(permissions) > MaxBatch {
		return nil, invalid("at most %d permissions per check", MaxBatch)
	}
	for _, r := range resources {
		if err := ValidateResourceURI(r); err != nil {
			return nil, err
		}
	}
	byURI := map[string]BatchResult{}
	for i := 0; i < len(resources); i += MaxBatch {
		chunk := resources[i:min(i+MaxBatch, len(resources))]
		res, err := c.Raw.BatchCheck(ctx, &pb.BatchCheckRequest{
			ProjectName: c.Project, PrincipalId: principal, ResourceUris: chunk, Permissions: permissions,
		})
		if err != nil {
			return nil, err
		}
		for _, r := range res.GetResults() {
			missing := r.GetMissingPermissions()
			if missing == nil {
				missing = []string{}
			}
			byURI[r.GetResourceUri()] = BatchResult{Resource: r.GetResourceUri(), Allowed: r.GetAllowed() && len(missing) == 0, Missing: missing}
		}
	}
	out := make([]BatchResult, 0, len(resources))
	for _, r := range resources {
		e, ok := byURI[r]
		if !ok {
			// Fail closed: every requested resource must have its own answer.
			return nil, &Error{Kind: KindOther, Message: fmt.Sprintf("inconsistent response: no BatchCheck result for %q", r)}
		}
		out = append(out, e)
	}
	return out, nil
}

// ListPermissions returns every permission in the project, ordered by name.
func (c *Client) ListPermissions(ctx context.Context, search string) ([]Permission, error) {
	out := []Permission{}
	err := paginate(ctx, func(p *paginationv1.PaginationRequest) (string, error) {
		res, err := c.Raw.ListPermissions(ctx, &pb.ListPermissionsRequest{ProjectName: c.Project, Pagination: p, Search: optString(search)})
		if err != nil {
			return "", err
		}
		for _, x := range res.GetPermissions() {
			out = append(out, permissionFromPB(x))
		}
		return res.GetPagination().GetNextCursor(), nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, err
}

// GetPermission returns one permission by name.
func (c *Client) GetPermission(ctx context.Context, name string) (*Permission, error) {
	res, err := c.Raw.GetPermission(ctx, &pb.GetPermissionRequest{ProjectName: c.Project, Name: name})
	if err != nil {
		return nil, err
	}
	p := permissionFromPB(res)
	return &p, nil
}

// CreatePermission creates a permission.
func (c *Client) CreatePermission(ctx context.Context, name, description string) (*Permission, error) {
	res, err := c.Raw.CreatePermission(ctx, &pb.CreatePermissionRequest{ProjectName: c.Project, Name: name, Description: description})
	if err != nil {
		// The API answers a clash with an existing permission (same name, other
		// description) with a bare Internal "failed to create permission".
		if isInternal(err) {
			if p, gerr := c.GetPermission(ctx, name); gerr == nil {
				return nil, alreadyExists("permission %q already exists with description %q; update it instead", name, p.Description)
			}
		}
		return nil, err
	}
	p := permissionFromPB(res)
	return &p, nil
}

// UpdatePermission replaces a permission's description and optionally renames it.
func (c *Client) UpdatePermission(ctx context.Context, name, newName, description string) (*Permission, error) {
	res, err := c.Raw.UpdatePermission(ctx, &pb.UpdatePermissionRequest{ProjectName: c.Project, Name: name, NewName: optString(newName), Description: description})
	if err != nil {
		return nil, err
	}
	p := permissionFromPB(res)
	return &p, nil
}

// DeletePermission deletes a permission. Deleting one that does not exist succeeds.
func (c *Client) DeletePermission(ctx context.Context, name string) error {
	_, err := c.Raw.DeletePermission(ctx, &pb.DeletePermissionRequest{ProjectName: c.Project, Name: name})
	// The API answers a delete of a missing permission with a bare Internal
	// "failed to delete permission"; treat it as done if the permission is gone.
	if err != nil && isInternal(err) {
		if _, gerr := c.GetPermission(ctx, name); IsNotFound(gerr) {
			return nil
		}
	}
	return err
}

// ListRoles returns every role in the project, ordered by name.
func (c *Client) ListRoles(ctx context.Context, search string) ([]Role, error) {
	out := []Role{}
	err := paginate(ctx, func(p *paginationv1.PaginationRequest) (string, error) {
		res, err := c.Raw.ListRoles(ctx, &pb.ListRolesRequest{ProjectName: c.Project, Pagination: p, Search: optString(search)})
		if err != nil {
			return "", err
		}
		for _, x := range res.GetRoles() {
			out = append(out, roleFromPB(x))
		}
		return res.GetPagination().GetNextCursor(), nil
	})
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name < out[j].Name || (out[i].Name == out[j].Name && out[i].ID < out[j].ID)
	})
	return out, err
}

// GetRole returns a role by ID.
func (c *Client) GetRole(ctx context.Context, id string) (*Role, error) {
	res, err := c.Raw.GetRole(ctx, &pb.GetRoleRequest{ProjectName: c.Project, Id: id})
	if err != nil {
		return nil, err
	}
	r := roleFromPB(res)
	return &r, nil
}

// ResolveRole finds a role by exact ID, or else by exact name.
func (c *Client) ResolveRole(ctx context.Context, ref string) (*Role, error) {
	roles, err := c.ListRoles(ctx, "")
	if err != nil {
		return nil, err
	}
	return FindRole(roles, ref)
}

// FindRole finds a role in roles by exact ID, or else by exact name.
func FindRole(roles []Role, ref string) (*Role, error) {
	for i := range roles {
		if roles[i].ID == ref {
			return &roles[i], nil
		}
	}
	var found []Role
	for _, r := range roles {
		if r.Name == ref {
			found = append(found, r)
		}
	}
	switch len(found) {
	case 0:
		return nil, &Error{Kind: KindNotFound, Message: fmt.Sprintf("role %q not found (looked up by ID and by name)", ref)}
	case 1:
		return &found[0], nil
	default:
		return nil, invalid("role name %q is ambiguous (%d roles); use the role ID", ref, len(found))
	}
}

// CreateRole creates a role and returns it with its ID.
func (c *Client) CreateRole(ctx context.Context, name, description string, permissions []string) (*Role, error) {
	res, err := c.Raw.CreateRole(ctx, &pb.CreateRoleRequest{ProjectName: c.Project, Name: name, Description: description, Permissions: uniq(permissions)})
	if err != nil {
		// The API answers a clash with an existing role of the same name (but other
		// permissions or description) with a bare Internal "failed to create role".
		if isInternal(err) {
			if roles, lerr := c.ListRoles(ctx, ""); lerr == nil {
				for _, r := range roles {
					if r.Name == name {
						return nil, alreadyExists("role %q already exists (ID %s) with other permissions or description; update it instead", name, r.ID)
					}
				}
			}
		}
		return nil, err
	}
	r := roleFromPB(res)
	return &r, nil
}

// UpdateRole replaces a role's name, description and permissions.
func (c *Client) UpdateRole(ctx context.Context, id, name, description string, permissions []string) (*Role, error) {
	res, err := c.Raw.UpdateRole(ctx, &pb.UpdateRoleRequest{ProjectName: c.Project, Id: id, Name: name, Description: description, Permissions: uniq(permissions)})
	if err != nil {
		return nil, err
	}
	r := roleFromPB(res)
	return &r, nil
}

// DeleteRole deletes a role by ID.
func (c *Client) DeleteRole(ctx context.Context, id string) error {
	_, err := c.Raw.DeleteRole(ctx, &pb.DeleteRoleRequest{ProjectName: c.Project, Id: id})
	return err
}

// Grant adds roles (by ID) and permissions to principal on resource. It is
// additive: nothing already granted is removed.
func (c *Client) Grant(ctx context.Context, principal, resource string, roleIDs, permissions []string) error {
	if err := ValidateResourceURI(resource); err != nil {
		return err
	}
	if len(roleIDs) == 0 && len(permissions) == 0 {
		return invalid("give at least one role or permission")
	}
	_, err := c.Raw.GrantUserPermissionsAndRolesOnResource(ctx, &pb.GrantUserPermissionsAndRolesOnResourceRequest{
		ProjectName: c.Project, UserId: principal, ResourceUri: resource, Roles: uniq(roleIDs), Permissions: uniq(permissions),
	})
	return err
}

// Revoke removes roles (by ID) and permissions from principal on resource.
func (c *Client) Revoke(ctx context.Context, principal, resource string, roleIDs, permissions []string) error {
	if err := ValidateResourceURI(resource); err != nil {
		return err
	}
	if len(roleIDs) == 0 && len(permissions) == 0 {
		return invalid("give at least one role or permission")
	}
	_, err := c.Raw.RevokeUserPermissionsAndRolesOnResource(ctx, &pb.RevokeUserPermissionsAndRolesOnResourceRequest{
		ProjectName: c.Project, UserId: principal, ResourceUri: resource, Roles: uniq(roleIDs), Permissions: uniq(permissions),
	})
	return err
}

// GetGrant returns what is granted to principal on exactly resource (not
// inherited grants). Role names are filled in from roles when given.
func (c *Client) GetGrant(ctx context.Context, principal, resource string, roles []Role) (*Grant, error) {
	if err := ValidateResourceURI(resource); err != nil {
		return nil, err
	}
	res, err := c.Raw.GetUserPermissionsAndRolesOnResource(ctx, &pb.GetUserPermissionsAndRolesOnResourceRequest{
		ProjectName: c.Project, UserId: principal, ResourceUri: resource,
	})
	if err != nil {
		return nil, err
	}
	names := map[string]string{}
	for _, r := range roles {
		names[r.ID] = r.Name
	}
	g := &Grant{Principal: principal, Resource: resource, Roles: []RoleRef{}, Permissions: append([]string{}, res.GetPermissions()...)}
	for _, id := range res.GetRoles() {
		g.Roles = append(g.Roles, RoleRef{ID: id, Name: names[id]})
	}
	normaliseGrant(g)
	return g, nil
}

// ListAssignments returns every grant made to principal, ordered by resource.
func (c *Client) ListAssignments(ctx context.Context, principal string) ([]Grant, error) {
	out := []Grant{}
	err := paginate(ctx, func(p *paginationv1.PaginationRequest) (string, error) {
		res, err := c.Raw.GetAllAssignmentsForPrincipal(ctx, &pb.GetAllAssignmentsForPrincipalRequest{ProjectName: c.Project, PrincipalId: principal, Pagination: p})
		if err != nil {
			return "", err
		}
		for _, a := range res.GetAssignments() {
			g := Grant{Principal: principal, Resource: a.GetResourceUri(), Roles: []RoleRef{}, Permissions: []string{}}
			for _, r := range a.GetRoles() {
				g.Roles = append(g.Roles, RoleRef{ID: r.GetId(), Name: r.GetName()})
			}
			for _, x := range a.GetPermissions() {
				g.Permissions = append(g.Permissions, x.GetName())
			}
			normaliseGrant(&g)
			out = append(out, g)
		}
		return res.GetPagination().GetNextCursor(), nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Resource < out[j].Resource })
	return out, err
}

// ListPrincipals returns the IDs of every principal with a grant in the
// project (groups included, as "group:<name>"), sorted.
func (c *Client) ListPrincipals(ctx context.Context, search string) ([]string, error) {
	out := []string{}
	err := paginate(ctx, func(p *paginationv1.PaginationRequest) (string, error) {
		res, err := c.Raw.ListPrincipals(ctx, &pb.ListPrincipalsRequest{ProjectName: c.Project, Pagination: p, Search: optString(search)})
		if err != nil {
			return "", err
		}
		out = append(out, res.GetPrincipals()...)
		return res.GetPagination().GetNextCursor(), nil
	})
	out = uniq(out)
	sort.Strings(out)
	return out, err
}

// ListAllGrants returns every grant in the project, ordered by principal then
// resource. It makes one call per principal.
func (c *Client) ListAllGrants(ctx context.Context) ([]Grant, error) {
	principals, err := c.ListPrincipals(ctx, "")
	if err != nil {
		return nil, err
	}
	out := []Grant{}
	for _, p := range principals {
		gs, err := c.ListAssignments(ctx, p)
		if err != nil {
			return nil, err
		}
		for _, g := range gs {
			if len(g.Roles) > 0 || len(g.Permissions) > 0 {
				out = append(out, g)
			}
		}
	}
	return out, nil
}

func normaliseGrant(g *Grant) {
	g.Permissions = uniq(g.Permissions)
	sort.Strings(g.Permissions)
	seen := map[string]bool{}
	roles := g.Roles[:0]
	for _, r := range g.Roles {
		if r.ID == "" || seen[r.ID] {
			continue
		}
		seen[r.ID] = true
		roles = append(roles, r)
	}
	g.Roles = roles
	sort.Slice(g.Roles, func(i, j int) bool {
		if g.Roles[i].Name != g.Roles[j].Name {
			return g.Roles[i].Name < g.Roles[j].Name
		}
		return g.Roles[i].ID < g.Roles[j].ID
	})
}

// ListGroups returns every group in the project, ordered by name.
func (c *Client) ListGroups(ctx context.Context, search string) ([]Group, error) {
	out := []Group{}
	err := paginate(ctx, func(p *paginationv1.PaginationRequest) (string, error) {
		res, err := c.Raw.ListGroups(ctx, &pb.ListGroupsRequest{ProjectName: c.Project, Pagination: p, Search: optString(search)})
		if err != nil {
			return "", err
		}
		for _, g := range res.GetGroups() {
			out = append(out, groupFromPB(g))
		}
		return res.GetPagination().GetNextCursor(), nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, err
}

// GetGroup returns a group by slug.
func (c *Client) GetGroup(ctx context.Context, name string) (*Group, error) {
	res, err := c.Raw.GetGroup(ctx, &pb.GetGroupRequest{ProjectName: c.Project, Name: name})
	if err != nil {
		return nil, err
	}
	g := groupFromPB(res)
	return &g, nil
}

// CreateGroup creates a group.
func (c *Client) CreateGroup(ctx context.Context, name, description string) (*Group, error) {
	res, err := c.Raw.CreateGroup(ctx, &pb.CreateGroupRequest{ProjectName: c.Project, Name: name, Description: description})
	if err != nil {
		return nil, err
	}
	g := groupFromPB(res)
	return &g, nil
}

// UpdateGroup replaces a group's description.
func (c *Client) UpdateGroup(ctx context.Context, name, description string) (*Group, error) {
	res, err := c.Raw.UpdateGroup(ctx, &pb.UpdateGroupRequest{ProjectName: c.Project, Name: name, Description: description})
	if err != nil {
		return nil, err
	}
	g := groupFromPB(res)
	return &g, nil
}

// DeleteGroup deletes a group with its memberships and every grant made to it.
func (c *Client) DeleteGroup(ctx context.Context, name string) error {
	_, err := c.Raw.DeleteGroup(ctx, &pb.DeleteGroupRequest{ProjectName: c.Project, Name: name})
	return err
}

// ListGroupMembers returns a group's member principal IDs, sorted.
func (c *Client) ListGroupMembers(ctx context.Context, name string) ([]string, error) {
	out := []string{}
	err := paginate(ctx, func(p *paginationv1.PaginationRequest) (string, error) {
		res, err := c.Raw.ListGroupMembers(ctx, &pb.ListGroupMembersRequest{ProjectName: c.Project, Name: name, Pagination: p})
		if err != nil {
			return "", err
		}
		for _, m := range res.GetMembers() {
			out = append(out, m.GetPrincipalId())
		}
		return res.GetPagination().GetNextCursor(), nil
	})
	sort.Strings(out)
	return out, err
}

// MembershipChange is the result of adding or removing group members.
type MembershipChange struct {
	// Changed are the principals added (or removed).
	Changed []string `json:"changed"`
	// Unchanged are the principals that were already members (or were not members).
	Unchanged []string `json:"unchanged"`
}

// AddGroupMembers adds principals to a group, 100 per call.
func (c *Client) AddGroupMembers(ctx context.Context, name string, principals []string) (*MembershipChange, error) {
	out := &MembershipChange{Changed: []string{}, Unchanged: []string{}}
	principals = uniq(principals)
	for i := 0; i < len(principals); i += MaxBatch {
		res, err := c.Raw.AddGroupMembers(ctx, &pb.AddGroupMembersRequest{ProjectName: c.Project, Name: name, PrincipalIds: principals[i:min(i+MaxBatch, len(principals))]})
		if err != nil {
			return out, err
		}
		out.Changed = append(out.Changed, res.GetAddedPrincipalIds()...)
		out.Unchanged = append(out.Unchanged, res.GetExistingPrincipalIds()...)
	}
	return out, nil
}

// RemoveGroupMembers removes principals from a group, 100 per call.
func (c *Client) RemoveGroupMembers(ctx context.Context, name string, principals []string) (*MembershipChange, error) {
	out := &MembershipChange{Changed: []string{}, Unchanged: []string{}}
	principals = uniq(principals)
	for i := 0; i < len(principals); i += MaxBatch {
		res, err := c.Raw.RemoveGroupMembers(ctx, &pb.RemoveGroupMembersRequest{ProjectName: c.Project, Name: name, PrincipalIds: principals[i:min(i+MaxBatch, len(principals))]})
		if err != nil {
			return out, err
		}
		out.Changed = append(out.Changed, res.GetRemovedPrincipalIds()...)
		out.Unchanged = append(out.Unchanged, res.GetNotMemberPrincipalIds()...)
	}
	return out, nil
}
