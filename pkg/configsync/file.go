// Package configsync implements Permio "config as code": parsing a permio.yaml
// file, exporting a project's current state as one, computing a plan (the
// diff between the file and the project) and applying it.
//
// It is used by `permio plan`, `permio apply` and `permio export`, and is kept
// free of CLI concerns so other tools can reuse it.
package configsync

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"

	"github.com/perms-io/permio-cli/pkg/permio"
)

// SchemaURL is the JSON Schema for the file, referenced from exported files
// for editor autocompletion.
const SchemaURL = "https://raw.githubusercontent.com/perms-io/permio-cli/main/schema/permio.schema.json"

// File is a permio.yaml file.
//
//	project: default
//	permissions: [document.read, document.edit]   # or {name, description} objects
//	roles:
//	  editor: { description: ..., permissions: [document.read, document.edit] }
//	groups:
//	  design: { description: ..., members: [user_123] }
//	grants:
//	  - { principal: group:design, resource: /projects/123, roles: [editor], permissions: [] }
type File struct {
	// Project is the project the file describes. Optional; defaults to the
	// configured project.
	Project string `yaml:"project,omitempty" json:"project,omitempty"`
	// Permissions are the project's permissions.
	Permissions []PermissionSpec `yaml:"permissions,omitempty" json:"permissions,omitempty"`
	// Roles are keyed by role name.
	Roles map[string]RoleSpec `yaml:"roles,omitempty" json:"roles,omitempty"`
	// Groups are keyed by group slug.
	Groups map[string]GroupSpec `yaml:"groups,omitempty" json:"groups,omitempty"`
	// Grants each state the full set of roles and permissions for one
	// (principal, resource) pair.
	Grants []GrantSpec `yaml:"grants,omitempty" json:"grants,omitempty"`
}

// PermissionSpec is a permission. In YAML it is either a bare name or a
// {name, description} object. A nil Description leaves the description as it
// is in the project.
type PermissionSpec struct {
	Name        string  `json:"name"`
	Description *string `json:"description,omitempty"`
}

// UnmarshalYAML accepts a scalar name or a {name, description} mapping.
func (p *PermissionSpec) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		p.Name = n.Value
		return nil
	}
	var obj struct {
		Name        string  `yaml:"name"`
		Description *string `yaml:"description"`
	}
	if n.Kind != yaml.MappingNode {
		return fmt.Errorf("line %d: a permission must be a name or a {name, description} object", n.Line)
	}
	// Strict: reject unknown keys.
	for i := 0; i < len(n.Content); i += 2 {
		if k := n.Content[i].Value; k != "name" && k != "description" {
			return fmt.Errorf("line %d: unknown permission field %q (allowed: name, description)", n.Content[i].Line, k)
		}
	}
	if err := n.Decode(&obj); err != nil {
		return err
	}
	p.Name, p.Description = obj.Name, obj.Description
	return nil
}

// MarshalYAML writes a bare name when there is no description.
func (p PermissionSpec) MarshalYAML() (any, error) {
	if p.Description == nil || *p.Description == "" {
		return p.Name, nil
	}
	return struct {
		Name        string `yaml:"name"`
		Description string `yaml:"description"`
	}{p.Name, *p.Description}, nil
}

// RoleSpec is a role. Permissions is the role's full permission set. A nil
// Description leaves the description as it is in the project.
type RoleSpec struct {
	Description *string  `yaml:"description,omitempty" json:"description,omitempty"`
	Permissions []string `yaml:"permissions" json:"permissions"`
}

// GroupSpec is a group. When Members is set it is the group's full member
// list; when omitted, members are not managed. A nil Description leaves the
// description as it is in the project.
type GroupSpec struct {
	Description *string   `yaml:"description,omitempty" json:"description,omitempty"`
	Members     *[]string `yaml:"members,omitempty" json:"members,omitempty"`
}

// GrantSpec is the full set of roles (by name) and permissions for one
// principal on one resource. Empty lists revoke everything on that pair.
type GrantSpec struct {
	Principal   string   `yaml:"principal" json:"principal"`
	Resource    string   `yaml:"resource" json:"resource"`
	Roles       []string `yaml:"roles,flow" json:"roles"`
	Permissions []string `yaml:"permissions,flow" json:"permissions"`
}

var (
	projectRe    = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
	permissionRe = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,128}$`)
	groupRe      = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)
)

// ValidProject reports whether name is a valid project name.
func ValidProject(name string) bool { return projectRe.MatchString(name) }

// Parse decodes and validates a permio.yaml file. Unknown fields are errors.
func Parse(data []byte) (*File, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	f := &File{}
	if err := dec.Decode(f); err != nil {
		if errors.Is(err, io.EOF) { // empty file
			return f, nil
		}
		return nil, fmt.Errorf("parsing config file: %w", err)
	}
	if err := f.Validate(); err != nil {
		return nil, err
	}
	return f, nil
}

// ValidationError lists every problem found in a file.
type ValidationError struct{ Problems []string }

func (e *ValidationError) Error() string {
	if len(e.Problems) == 1 {
		return "invalid config file: " + e.Problems[0]
	}
	return "invalid config file:\n  - " + strings.Join(e.Problems, "\n  - ")
}

func validRoleName(name string) bool {
	if name == "" || len(name) > 128 {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// Validate checks names, formats and duplicates. References between objects
// are checked by ComputePlan, which also knows the project's current state.
func (f *File) Validate() error {
	var probs []string
	add := func(format string, args ...any) { probs = append(probs, fmt.Sprintf(format, args...)) }

	if f.Project != "" && !ValidProject(f.Project) {
		add("project %q must be 1-32 lower-case letters, digits or hyphens", f.Project)
	}
	seen := map[string]bool{}
	for _, p := range f.Permissions {
		switch {
		case !permissionRe.MatchString(p.Name):
			add("permission %q must be 1-128 characters of a-z, A-Z, 0-9, '.', '_' or '-'", p.Name)
		case seen[p.Name]:
			add("permission %q is listed twice", p.Name)
		}
		seen[p.Name] = true
	}
	for _, name := range sortedKeys(f.Roles) {
		if !validRoleName(name) {
			add("role name %q must be 1-128 characters without control characters", name)
		}
		dup := map[string]bool{}
		for _, p := range f.Roles[name].Permissions {
			if !permissionRe.MatchString(p) {
				add("role %q: invalid permission name %q", name, p)
			}
			if dup[p] {
				add("role %q: permission %q is listed twice", name, p)
			}
			dup[p] = true
		}
	}
	for _, name := range sortedKeys(f.Groups) {
		if !groupRe.MatchString(name) {
			add("group %q must be 1-64 lower-case letters, digits or hyphens", name)
		}
		g := f.Groups[name]
		if g.Description != nil && len(*g.Description) > 1024 {
			add("group %q: description is longer than 1024 characters", name)
		}
		if g.Members != nil {
			dup := map[string]bool{}
			for _, m := range *g.Members {
				switch {
				case m == "":
					add("group %q: empty member", name)
				case strings.HasPrefix(m, permio.GroupPrefix):
					add("group %q: member %q is a group; groups cannot contain groups", name, m)
				case dup[m]:
					add("group %q: member %q is listed twice", name, m)
				}
				dup[m] = true
			}
		}
	}
	pairs := map[string]int{}
	for i, g := range f.Grants {
		where := fmt.Sprintf("grants[%d]", i)
		if g.Principal == "" {
			add("%s: principal is required", where)
		}
		if err := permio.ValidateResourceURI(g.Resource); err != nil {
			add("%s: %v", where, err)
		}
		key := g.Principal + "\x00" + g.Resource
		if j, ok := pairs[key]; ok {
			add("%s: principal %q on %q is already listed in grants[%d]; list each pair once", where, g.Principal, g.Resource, j)
		}
		pairs[key] = i
		for _, p := range g.Permissions {
			if !permissionRe.MatchString(p) {
				add("%s: invalid permission name %q", where, p)
			}
		}
		for _, r := range g.Roles {
			if r == "" {
				add("%s: empty role name", where)
			}
		}
	}
	if len(probs) > 0 {
		return &ValidationError{Problems: probs}
	}
	return nil
}

// Marshal encodes the file as YAML with a schema comment for editors.
func (f *File) Marshal() ([]byte, error) {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "# yaml-language-server: $schema=%s\n", SchemaURL)
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(f); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
