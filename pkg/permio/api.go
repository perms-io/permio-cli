package permio

import (
	"context"
	"fmt"
	"slices"
	"sort"

	sdk "github.com/perms-io/permio-go"
)

func listOpts(search string) *sdk.ListOptions { return &sdk.ListOptions{Search: search} }

// Check reports whether principal holds every permission on every resource.
// A denial is a normal result, not an error.
func (c *Client) Check(ctx context.Context, principal string, resources, permissions []string) (*CheckResult, error) {
	return c.SDK.CheckDetailed(ctx, sdk.CheckRequest{Principal: principal, Resources: resources, Permissions: permissions})
}

// BatchCheck checks each resource separately, in request order. More than 100
// resources are split into several calls.
func (c *Client) BatchCheck(ctx context.Context, principal string, resources, permissions []string) ([]BatchResult, error) {
	return c.SDK.BatchCheckDetailed(ctx, principal, permissions, resources)
}

// ListPermissions returns every permission in the project, ordered by name.
func (c *Client) ListPermissions(ctx context.Context, search string) ([]Permission, error) {
	out, err := sdk.Collect(c.SDK.ListPermissions(ctx, listOpts(search)))
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, err
}

// GetPermission returns one permission by name.
func (c *Client) GetPermission(ctx context.Context, name string) (*Permission, error) {
	return c.SDK.GetPermission(ctx, name)
}

// CreatePermission creates a permission.
func (c *Client) CreatePermission(ctx context.Context, name, description string) (*Permission, error) {
	return c.SDK.CreatePermission(ctx, name, description)
}

// UpdatePermission replaces a permission's description and optionally renames it.
func (c *Client) UpdatePermission(ctx context.Context, name, newName, description string) (*Permission, error) {
	return c.SDK.UpdatePermission(ctx, name, newName, description)
}

// DeletePermission deletes a permission. Deleting one that does not exist succeeds.
func (c *Client) DeletePermission(ctx context.Context, name string) error {
	return c.SDK.DeletePermission(ctx, name)
}

// ListRoles returns every role in the project, ordered by name.
func (c *Client) ListRoles(ctx context.Context, search string) ([]Role, error) {
	out, err := sdk.Collect(c.SDK.ListRoles(ctx, listOpts(search)))
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name < out[j].Name || (out[i].Name == out[j].Name && out[i].ID < out[j].ID)
	})
	return out, err
}

// GetRole returns a role by ID.
func (c *Client) GetRole(ctx context.Context, id string) (*Role, error) {
	return c.SDK.GetRole(ctx, id)
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
	return c.SDK.CreateRole(ctx, name, description, permissions)
}

// UpdateRole replaces a role's name, description and permissions.
func (c *Client) UpdateRole(ctx context.Context, id, name, description string, permissions []string) (*Role, error) {
	return c.SDK.UpdateRole(ctx, id, name, description, permissions)
}

// DeleteRole deletes a role by ID.
func (c *Client) DeleteRole(ctx context.Context, id string) error {
	return c.SDK.DeleteRole(ctx, id)
}

// Grant adds roles (by ID) and permissions to principal on resource. It is
// additive: nothing already granted is removed.
func (c *Client) Grant(ctx context.Context, principal, resource string, roleIDs, permissions []string) error {
	return c.SDK.Grant(ctx, sdk.GrantRequest{Principal: principal, Resource: resource, Roles: roleIDs, Permissions: permissions})
}

// Revoke removes roles (by ID) and permissions from principal on resource.
func (c *Client) Revoke(ctx context.Context, principal, resource string, roleIDs, permissions []string) error {
	return c.SDK.Revoke(ctx, sdk.GrantRequest{Principal: principal, Resource: resource, Roles: roleIDs, Permissions: permissions})
}

// GetGrant returns what is granted to principal on exactly resource (not
// inherited grants). Role names are filled in from roles when given.
func (c *Client) GetGrant(ctx context.Context, principal, resource string, roles []Role) (*Grant, error) {
	g, err := c.SDK.GetGrant(ctx, principal, resource)
	if err != nil {
		return nil, err
	}
	names := map[string]string{}
	for _, r := range roles {
		names[r.ID] = r.Name
	}
	for i := range g.Roles {
		g.Roles[i].Name = names[g.Roles[i].ID]
	}
	sortRoleRefs(g.Roles)
	return g, nil
}

func sortRoleRefs(refs []RoleRef) {
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].Name != refs[j].Name {
			return refs[i].Name < refs[j].Name
		}
		return refs[i].ID < refs[j].ID
	})
}

// ListAssignments returns every grant made to principal, ordered by resource.
func (c *Client) ListAssignments(ctx context.Context, principal string) ([]Grant, error) {
	out, err := sdk.Collect(c.SDK.ListAssignments(ctx, principal, nil))
	sort.Slice(out, func(i, j int) bool { return out[i].Resource < out[j].Resource })
	return out, err
}

// ListPrincipals returns the IDs of every principal with a grant in the
// project (groups included, as "group:<name>"), sorted.
func (c *Client) ListPrincipals(ctx context.Context, search string) ([]string, error) {
	out, err := sdk.Collect(c.SDK.ListPrincipals(ctx, listOpts(search)))
	slices.Sort(out)
	return slices.Compact(out), err
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

// ListGroups returns every group in the project, ordered by name.
func (c *Client) ListGroups(ctx context.Context, search string) ([]Group, error) {
	out, err := sdk.Collect(c.SDK.Groups().List(ctx, listOpts(search)))
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, err
}

// GetGroup returns a group by slug.
func (c *Client) GetGroup(ctx context.Context, name string) (*Group, error) {
	return c.SDK.Groups().Get(ctx, name)
}

// CreateGroup creates a group.
func (c *Client) CreateGroup(ctx context.Context, name, description string) (*Group, error) {
	return c.SDK.Groups().Create(ctx, name, description)
}

// UpdateGroup replaces a group's description.
func (c *Client) UpdateGroup(ctx context.Context, name, description string) (*Group, error) {
	return c.SDK.Groups().Update(ctx, name, description)
}

// DeleteGroup deletes a group with its memberships and every grant made to it.
func (c *Client) DeleteGroup(ctx context.Context, name string) error {
	return c.SDK.Groups().Delete(ctx, name)
}

// ListGroupMembers returns a group's member principal IDs, sorted.
func (c *Client) ListGroupMembers(ctx context.Context, name string) ([]string, error) {
	members, err := sdk.Collect(c.SDK.Groups().ListMembers(ctx, name, nil))
	out := make([]string, 0, len(members))
	for _, m := range members {
		out = append(out, m.PrincipalID)
	}
	sort.Strings(out)
	return out, err
}

// AddGroupMembers adds principals to a group, 100 per call. The SDK takes at
// most MaxBatch principals per write, so larger lists are split here. If a
// call fails, the result covers the calls that succeeded before it.
func (c *Client) AddGroupMembers(ctx context.Context, name string, principals []string) (*MembershipChange, error) {
	return c.inMemberBatches(ctx, name, principals, c.SDK.Groups().AddMembers)
}

// RemoveGroupMembers removes principals from a group, 100 per call, like
// AddGroupMembers.
func (c *Client) RemoveGroupMembers(ctx context.Context, name string, principals []string) (*MembershipChange, error) {
	return c.inMemberBatches(ctx, name, principals, c.SDK.Groups().RemoveMembers)
}

func (c *Client) inMemberBatches(ctx context.Context, name string, principals []string, write func(context.Context, string, []string) (*MembershipChange, error)) (*MembershipChange, error) {
	if len(principals) <= MaxBatch {
		// One write; the SDK validates and de-duplicates.
		return write(ctx, name, principals)
	}
	out := &MembershipChange{Changed: []string{}, Unchanged: []string{}}
	seen := make(map[string]bool, len(principals))
	var unique []string
	for _, p := range principals {
		if !seen[p] {
			seen[p] = true
			unique = append(unique, p)
		}
	}
	for batch := range slices.Chunk(unique, MaxBatch) {
		res, err := write(ctx, name, batch)
		if err != nil {
			return out, err
		}
		out.Changed = append(out.Changed, res.Changed...)
		out.Unchanged = append(out.Unchanged, res.Unchanged...)
	}
	return out, nil
}

// ListAccess answers "where may principal use permission at or below under?",
// following every page. Access through roles and groups counts.
func (c *Client) ListAccess(ctx context.Context, principal, permission, under string) (*AccessScopes, error) {
	return c.SDK.ListAccess(ctx, principal, permission, under)
}

// WhoHasAccess lists the principals with a grant on resource, an ancestor of
// it, or a "_" wildcard URI matching it. With permission set only grants that
// confer it count. With expandGroups, members of listed groups are listed too.
func (c *Client) WhoHasAccess(ctx context.Context, resource, permission string, expandGroups bool) ([]AccessEntry, error) {
	return c.SDK.WhoHasAccess(ctx, resource, &sdk.WhoHasAccessOptions{Permission: permission, ExpandGroups: expandGroups})
}
