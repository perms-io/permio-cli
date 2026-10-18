package configsync

import (
	"context"
	"fmt"
	"sort"

	"github.com/PrivateJAR/permio-cli/pkg/permio"
)

// GroupState is a group with its members.
type GroupState struct {
	permio.Group
	Members []string
}

// State is a project's current permissions, roles, groups and grants.
type State struct {
	Permissions map[string]permio.Permission
	// Roles are keyed by role ID.
	Roles  map[string]permio.Role
	Groups map[string]GroupState
	// Grants are keyed by principal + "\x00" + resource.
	Grants map[string]permio.Grant
}

func pairKey(principal, resource string) string { return principal + "\x00" + resource }

// Fetch reads a project's current state. It lists everything, so it makes one
// call per page of each object type, one per group (members) and one per
// principal (grants).
func Fetch(ctx context.Context, c *permio.Client) (*State, error) {
	s := &State{
		Permissions: map[string]permio.Permission{},
		Roles:       map[string]permio.Role{},
		Groups:      map[string]GroupState{},
		Grants:      map[string]permio.Grant{},
	}
	perms, err := c.ListPermissions(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("listing permissions: %w", err)
	}
	for _, p := range perms {
		s.Permissions[p.Name] = p
	}
	roles, err := c.ListRoles(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("listing roles: %w", err)
	}
	for _, r := range roles {
		s.Roles[r.ID] = r
	}
	groups, err := c.ListGroups(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("listing groups: %w", err)
	}
	for _, g := range groups {
		members, err := c.ListGroupMembers(ctx, g.Name)
		if err != nil {
			return nil, fmt.Errorf("listing members of group %q: %w", g.Name, err)
		}
		s.Groups[g.Name] = GroupState{Group: g, Members: members}
	}
	grants, err := c.ListAllGrants(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing grants: %w", err)
	}
	for _, g := range grants {
		s.Grants[pairKey(g.Principal, g.Resource)] = g
	}
	return s, nil
}

// rolesByName maps role names to roles; names held by more than one role map
// to nil.
func (s *State) rolesByName() map[string]*permio.Role {
	out := map[string]*permio.Role{}
	for id := range s.Roles {
		r := s.Roles[id]
		if _, dup := out[r.Name]; dup {
			out[r.Name] = nil
			continue
		}
		out[r.Name] = &r
	}
	return out
}

// Export returns the state as a File that round-trips: planning the exported
// file against the same project shows no changes.
func (s *State) Export(project string) (*File, error) {
	f := &File{Project: project, Roles: map[string]RoleSpec{}, Groups: map[string]GroupSpec{}}
	for _, name := range sortedKeys(s.Permissions) {
		p := s.Permissions[name]
		spec := PermissionSpec{Name: name}
		if p.Description != "" {
			d := p.Description
			spec.Description = &d
		}
		f.Permissions = append(f.Permissions, spec)
	}
	byName := s.rolesByName()
	for name, r := range byName {
		if r == nil {
			return nil, fmt.Errorf("cannot export: more than one role is named %q; rename one so roles can be referenced by name", name)
		}
		spec := RoleSpec{Permissions: append([]string{}, r.Permissions...)}
		sort.Strings(spec.Permissions)
		if r.Description != "" {
			d := r.Description
			spec.Description = &d
		}
		f.Roles[name] = spec
	}
	for name, g := range s.Groups {
		members := append([]string{}, g.Members...)
		sort.Strings(members)
		spec := GroupSpec{Members: &members}
		if g.Description != "" {
			d := g.Description
			spec.Description = &d
		}
		f.Groups[name] = spec
	}
	for _, key := range sortedKeys(s.Grants) {
		g := s.Grants[key]
		spec := GrantSpec{Principal: g.Principal, Resource: g.Resource, Roles: []string{}, Permissions: append([]string{}, g.Permissions...)}
		for _, r := range g.Roles {
			name := r.Name
			if name == "" {
				if known, ok := s.Roles[r.ID]; ok {
					name = known.Name
				}
			}
			spec.Roles = append(spec.Roles, name)
		}
		sort.Strings(spec.Roles)
		sort.Strings(spec.Permissions)
		f.Grants = append(f.Grants, spec)
	}
	if len(f.Roles) == 0 {
		f.Roles = nil
	}
	if len(f.Groups) == 0 {
		f.Groups = nil
	}
	return f, nil
}
