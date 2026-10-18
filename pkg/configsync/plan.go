package configsync

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/PrivateJAR/permio-cli/pkg/permio"
)

// Action is what a change does.
type Action string

const (
	Create Action = "create"
	Update Action = "update"
	Delete Action = "delete"
)

// Kind is the type of object a change touches.
type Kind string

const (
	KindPermission Kind = "permission"
	KindRole       Kind = "role"
	KindGroup      Kind = "group"
	KindMember     Kind = "member"
	KindGrant      Kind = "grant"
)

// StringChange is a field changing from one value to another.
type StringChange struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// Change is one step of a plan. The JSON shape is stable.
type Change struct {
	Action Action `json:"action"`
	Kind   Kind   `json:"kind"`
	// Name identifies the object: a permission or role name, a group slug,
	// "<group>/<principal>" for a member, "<principal> <resource>" for a grant.
	Name string `json:"name"`

	RoleID      string        `json:"role_id,omitempty"`
	Group       string        `json:"group,omitempty"`
	Principal   string        `json:"principal,omitempty"`
	Resource    string        `json:"resource,omitempty"`
	Description *StringChange `json:"description,omitempty"`

	// Permissions added to / removed from a role or grant (all of them for a
	// create or delete).
	AddPermissions    []string `json:"add_permissions,omitempty"`
	RemovePermissions []string `json:"remove_permissions,omitempty"`
	// Roles (by name) added to / removed from a grant.
	AddRoles    []string `json:"add_roles,omitempty"`
	RemoveRoles []string `json:"remove_roles,omitempty"`

	// For apply.
	description   string   // final description (permission, role, group)
	finalPerms    []string // final role permissions
	removeRoleIDs []string // grant roles to revoke, by ID
	addRoleRefs   []string // grant roles to add, by name (or existing ID)
}

// Summary counts changes by action.
type Summary struct {
	Create int `json:"create"`
	Update int `json:"update"`
	Delete int `json:"delete"`
}

// Plan is the ordered list of changes that makes a project match a file.
// Creates and updates come first in dependency order (permissions, roles,
// groups, members, grants); deletes follow in reverse order.
type Plan struct {
	Project string   `json:"project"`
	Prune   bool     `json:"prune"`
	Changes []Change `json:"changes"`
	Summary Summary  `json:"summary"`
}

// Empty reports whether the plan has no changes.
func (p *Plan) Empty() bool { return len(p.Changes) == 0 }

// Options control planning.
type Options struct {
	// Prune also deletes objects in the project that are not in the file:
	// permissions, roles, groups and grants for (principal, resource) pairs the
	// file does not list.
	Prune bool
}

func setOf(values []string) map[string]bool {
	m := make(map[string]bool, len(values))
	for _, v := range values {
		m[v] = true
	}
	return m
}

func diff(want, have []string) (add, remove []string) {
	w, h := setOf(want), setOf(have)
	for v := range w {
		if !h[v] {
			add = append(add, v)
		}
	}
	for v := range h {
		if !w[v] {
			remove = append(remove, v)
		}
	}
	sort.Strings(add)
	sort.Strings(remove)
	return add, remove
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// ComputePlan diffs the desired file against the current state.
//
// Semantics: objects in the file are created or updated. A role's permission
// list, a group's member list (when given) and a grant's roles and permissions
// are each the full set, so extra entries are removed even without Prune.
// A nil description is left as it is. With Prune, permissions, roles, groups
// and grant pairs that are not in the file are deleted.
func ComputePlan(desired *File, cur *State, opts Options) (*Plan, error) {
	if err := desired.Validate(); err != nil {
		return nil, err
	}
	plan := &Plan{Project: desired.Project, Prune: opts.Prune, Changes: []Change{}}
	var probs []string
	problem := func(format string, args ...any) { probs = append(probs, fmt.Sprintf(format, args...)) }

	// Which permissions exist once the plan has run.
	desiredPerms := map[string]bool{}
	for _, p := range desired.Permissions {
		desiredPerms[p.Name] = true
	}
	permExists := func(name string) bool {
		if desiredPerms[name] {
			return true
		}
		_, ok := cur.Permissions[name]
		return ok && !opts.Prune
	}

	// 1. Permissions.
	for _, p := range desired.Permissions {
		have, ok := cur.Permissions[p.Name]
		switch {
		case !ok:
			plan.Changes = append(plan.Changes, Change{Action: Create, Kind: KindPermission, Name: p.Name, description: deref(p.Description),
				Description: descChange("", p.Description)})
		case p.Description != nil && *p.Description != have.Description:
			plan.Changes = append(plan.Changes, Change{Action: Update, Kind: KindPermission, Name: p.Name, description: *p.Description,
				Description: &StringChange{From: have.Description, To: *p.Description}})
		}
	}

	// 2. Roles.
	byName := cur.rolesByName()
	for _, name := range sortedKeys(desired.Roles) {
		spec := desired.Roles[name]
		for _, p := range spec.Permissions {
			if !permExists(p) {
				problem("role %q uses permission %q, which is not in the file%s", name, p, pruneHint(cur.Permissions, p, opts.Prune))
			}
		}
		have, ok := byName[name]
		if ok && have == nil {
			problem("more than one role in the project is named %q; rename one so the file can refer to it", name)
			continue
		}
		perms := append([]string{}, spec.Permissions...)
		sort.Strings(perms)
		if !ok {
			plan.Changes = append(plan.Changes, Change{Action: Create, Kind: KindRole, Name: name, description: deref(spec.Description),
				Description: descChange("", spec.Description), AddPermissions: perms, finalPerms: perms})
			continue
		}
		add, remove := diff(perms, have.Permissions)
		desc := have.Description
		var dc *StringChange
		if spec.Description != nil && *spec.Description != have.Description {
			desc = *spec.Description
			dc = &StringChange{From: have.Description, To: desc}
		}
		if len(add) > 0 || len(remove) > 0 || dc != nil {
			plan.Changes = append(plan.Changes, Change{Action: Update, Kind: KindRole, Name: name, RoleID: have.ID, description: desc,
				Description: dc, AddPermissions: add, RemovePermissions: remove, finalPerms: perms})
		}
	}
	roleExists := func(ref string) bool {
		if _, ok := desired.Roles[ref]; ok {
			return true
		}
		if opts.Prune {
			return false
		}
		if r, ok := byName[ref]; ok && r != nil {
			return true
		}
		_, ok := cur.Roles[ref] // a role ID
		return ok
	}

	// 3. Groups and 4. members.
	var memberChanges []Change
	for _, name := range sortedKeys(desired.Groups) {
		spec := desired.Groups[name]
		have, ok := cur.Groups[name]
		if !ok {
			plan.Changes = append(plan.Changes, Change{Action: Create, Kind: KindGroup, Name: name, description: deref(spec.Description),
				Description: descChange("", spec.Description)})
		} else if spec.Description != nil && *spec.Description != have.Description {
			plan.Changes = append(plan.Changes, Change{Action: Update, Kind: KindGroup, Name: name, description: *spec.Description,
				Description: &StringChange{From: have.Description, To: *spec.Description}})
		}
		if spec.Members == nil {
			continue
		}
		add, remove := diff(*spec.Members, have.Members)
		for _, m := range add {
			memberChanges = append(memberChanges, Change{Action: Create, Kind: KindMember, Name: name + "/" + m, Group: name, Principal: m})
		}
		for _, m := range remove {
			memberChanges = append(memberChanges, Change{Action: Delete, Kind: KindMember, Name: name + "/" + m, Group: name, Principal: m})
		}
	}
	plan.Changes = append(plan.Changes, memberChanges...)
	groupExists := func(slug string) bool {
		if _, ok := desired.Groups[slug]; ok {
			return true
		}
		_, ok := cur.Groups[slug]
		return ok && !opts.Prune
	}

	// 5. Grants.
	listed := map[string]bool{}
	for i, g := range desired.Grants {
		key := pairKey(g.Principal, g.Resource)
		listed[key] = true
		if slug, ok := strings.CutPrefix(g.Principal, permio.GroupPrefix); ok && !groupExists(slug) {
			problem("grants[%d]: group %q is not in the file%s", i, slug, pruneHintGroup(cur.Groups, slug, opts.Prune))
		}
		for _, p := range g.Permissions {
			if !permExists(p) {
				problem("grants[%d]: permission %q is not in the file%s", i, p, pruneHint(cur.Permissions, p, opts.Prune))
			}
		}
		for _, r := range g.Roles {
			if !roleExists(r) {
				problem("grants[%d]: role %q is not in the file or the project", i, r)
			}
		}
		have, exists := cur.Grants[key]
		haveRoleNames := map[string]string{} // name -> id
		for _, r := range have.Roles {
			haveRoleNames[roleName(cur, r)] = r.ID
		}
		var addRoles, removeRoles, removeIDs []string
		wantRoles := map[string]bool{}
		for _, r := range g.Roles {
			name := r
			if _, inFile := desired.Roles[r]; !inFile {
				if known, ok := cur.Roles[r]; ok {
					name = known.Name // referenced by ID
				}
			}
			wantRoles[name] = true
			if _, ok := haveRoleNames[name]; !ok {
				addRoles = append(addRoles, name)
			}
		}
		for name, id := range haveRoleNames {
			if !wantRoles[name] {
				removeRoles = append(removeRoles, name)
				removeIDs = append(removeIDs, id)
			}
		}
		sort.Strings(addRoles)
		sort.Strings(removeRoles)
		sort.Strings(removeIDs)
		addPerms, removePerms := diff(g.Permissions, have.Permissions)
		if len(addRoles)+len(removeRoles)+len(addPerms)+len(removePerms) == 0 {
			continue
		}
		action := Update
		switch {
		case !exists:
			action = Create
		case len(g.Roles) == 0 && len(g.Permissions) == 0:
			action = Delete
		}
		plan.Changes = append(plan.Changes, Change{Action: action, Kind: KindGrant, Name: g.Principal + " " + g.Resource,
			Principal: g.Principal, Resource: g.Resource, AddRoles: addRoles, RemoveRoles: removeRoles,
			AddPermissions: addPerms, RemovePermissions: removePerms, addRoleRefs: addRoles, removeRoleIDs: removeIDs})
	}
	if len(probs) > 0 {
		return nil, &ValidationError{Problems: probs}
	}

	if opts.Prune {
		// Deletes, in reverse dependency order: grants, groups, roles, permissions.
		for _, key := range sortedKeys(cur.Grants) {
			if listed[key] {
				continue
			}
			g := cur.Grants[key]
			var names, ids []string
			for _, r := range g.Roles {
				names = append(names, roleName(cur, r))
				ids = append(ids, r.ID)
			}
			sort.Strings(names)
			plan.Changes = append(plan.Changes, Change{Action: Delete, Kind: KindGrant, Name: g.Principal + " " + g.Resource,
				Principal: g.Principal, Resource: g.Resource, RemoveRoles: names, RemovePermissions: append([]string{}, g.Permissions...),
				removeRoleIDs: ids})
		}
		for _, name := range sortedKeys(cur.Groups) {
			if _, ok := desired.Groups[name]; !ok {
				plan.Changes = append(plan.Changes, Change{Action: Delete, Kind: KindGroup, Name: name})
			}
		}
		var roleDeletes []Change
		for id, r := range cur.Roles {
			if _, ok := desired.Roles[r.Name]; !ok {
				roleDeletes = append(roleDeletes, Change{Action: Delete, Kind: KindRole, Name: r.Name, RoleID: id})
			}
		}
		sort.Slice(roleDeletes, func(i, j int) bool {
			if roleDeletes[i].Name != roleDeletes[j].Name {
				return roleDeletes[i].Name < roleDeletes[j].Name
			}
			return roleDeletes[i].RoleID < roleDeletes[j].RoleID
		})
		plan.Changes = append(plan.Changes, roleDeletes...)
		for _, name := range sortedKeys(cur.Permissions) {
			if !desiredPerms[name] {
				plan.Changes = append(plan.Changes, Change{Action: Delete, Kind: KindPermission, Name: name})
			}
		}
	}

	for _, c := range plan.Changes {
		switch c.Action {
		case Create:
			plan.Summary.Create++
		case Update:
			plan.Summary.Update++
		case Delete:
			plan.Summary.Delete++
		}
	}
	return plan, nil
}

func roleName(cur *State, r permio.RoleRef) string {
	if r.Name != "" {
		return r.Name
	}
	if known, ok := cur.Roles[r.ID]; ok {
		return known.Name
	}
	return r.ID
}

func descChange(from string, to *string) *StringChange {
	if to == nil || *to == from {
		return nil
	}
	return &StringChange{From: from, To: *to}
}

func pruneHint(perms map[string]permio.Permission, name string, prune bool) string {
	if _, ok := perms[name]; ok && prune {
		return " (it exists in the project but --prune would delete it; add it to permissions)"
	}
	if prune {
		return ""
	}
	return " or the project"
}

func pruneHintGroup(groups map[string]GroupState, slug string, prune bool) string {
	if _, ok := groups[slug]; ok && prune {
		return " (it exists in the project but --prune would delete it; add it to groups)"
	}
	if prune {
		return ""
	}
	return " or the project"
}

var symbols = map[Action]string{Create: "+", Update: "~", Delete: "-"}

// Describe returns a one-line, human-readable description of the change.
func (c Change) Describe() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s ", symbols[c.Action], c.Kind)
	switch c.Kind {
	case KindMember:
		fmt.Fprintf(&b, "%s in group %s", c.Principal, c.Group)
	case KindGrant:
		fmt.Fprintf(&b, "%s on %s", c.Principal, c.Resource)
	default:
		b.WriteString(c.Name)
	}
	var details []string
	if c.Description != nil {
		details = append(details, fmt.Sprintf("description: %q -> %q", c.Description.From, c.Description.To))
	}
	if list := plusMinus(c.AddRoles, c.RemoveRoles, c.Action); list != "" {
		details = append(details, "roles: "+list)
	}
	if list := plusMinus(c.AddPermissions, c.RemovePermissions, c.Action); list != "" {
		details = append(details, "permissions: "+list)
	}
	if len(details) > 0 {
		b.WriteString("  (" + strings.Join(details, "; ") + ")")
	}
	return b.String()
}

func plusMinus(add, remove []string, action Action) string {
	if action == Create && len(remove) == 0 {
		return strings.Join(add, ", ")
	}
	if action == Delete && len(add) == 0 {
		return strings.Join(remove, ", ")
	}
	var parts []string
	for _, a := range add {
		parts = append(parts, "+"+a)
	}
	for _, r := range remove {
		parts = append(parts, "-"+r)
	}
	return strings.Join(parts, ", ")
}

// Render writes the plan in a human-readable form.
func (p *Plan) Render(w io.Writer) {
	if p.Empty() {
		fmt.Fprintf(w, "No changes. Project %q matches the file.\n", p.Project)
		return
	}
	fmt.Fprintf(w, "Plan for project %q:\n\n", p.Project)
	for _, c := range p.Changes {
		fmt.Fprintf(w, "  %s\n", c.Describe())
	}
	fmt.Fprintf(w, "\nPlan: %d to create, %d to update, %d to delete.\n", p.Summary.Create, p.Summary.Update, p.Summary.Delete)
	if !p.Prune {
		fmt.Fprintln(w, "Objects in the project but not in the file are kept; use --prune to delete them.")
	}
}
