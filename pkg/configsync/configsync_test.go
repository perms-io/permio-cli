package configsync

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/perms-io/permio-cli/pkg/apikey"
	"github.com/perms-io/permio-cli/pkg/fakeserver"
	"github.com/perms-io/permio-cli/pkg/permio"
)

func TestParseForms(t *testing.T) {
	f, err := Parse([]byte(`
project: my-app
permissions:
  - a.read
  - name: a.write
    description: Write
roles:
  r: { permissions: [a.read] }
groups:
  g: { description: G }
  h: { members: [] }
`))
	if err != nil {
		t.Fatal(err)
	}
	if f.Permissions[0].Description != nil || deref(f.Permissions[1].Description) != "Write" {
		t.Fatalf("permissions: %+v", f.Permissions)
	}
	if f.Groups["g"].Members != nil {
		t.Fatal("omitted members must be unmanaged (nil)")
	}
	if f.Groups["h"].Members == nil || len(*f.Groups["h"].Members) != 0 {
		t.Fatal("members: [] must be an empty managed list")
	}
	if _, err := Parse([]byte("permissions:\n  - {name: a, colour: red}\n")); err == nil {
		t.Fatal("unknown permission field accepted")
	}
	if f, err := Parse(nil); err != nil || f == nil {
		t.Fatalf("empty file: %v", err)
	}
	if _, err := Parse([]byte("project: Bad_Name\n")); err == nil {
		t.Fatal("bad project accepted")
	}
}

func TestMarshalRoundTrip(t *testing.T) {
	d := "Write"
	members := []string{"u1"}
	f := &File{
		Project:     "p",
		Permissions: []PermissionSpec{{Name: "a.read"}, {Name: "a.write", Description: &d}},
		Roles:       map[string]RoleSpec{"r": {Permissions: []string{"a.read"}}},
		Groups:      map[string]GroupSpec{"g": {Members: &members}},
		Grants:      []GrantSpec{{Principal: "group:g", Resource: "/x", Roles: []string{"r"}, Permissions: []string{}}},
	}
	data, err := f.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "- a.read\n") || !strings.Contains(string(data), "description: Write") {
		t.Fatalf("marshal:\n%s", data)
	}
	g, err := Parse(data)
	if err != nil {
		t.Fatalf("reparse: %v\n%s", err, data)
	}
	again, _ := g.Marshal()
	if string(again) != string(data) {
		t.Fatalf("not stable:\n%s\n---\n%s", data, again)
	}
}

// The package is usable without the CLI: fetch, plan, apply, export.
func TestLibraryUse(t *testing.T) {
	srv := fakeserver.New()
	key, _ := apikey.WithChecksum("LIBRARYkey0123456789abcdefghijkl")
	srv.AddKey(key, "default", true)
	c, err := permio.New(permio.Options{APIKey: key, Address: "localhost:1", Insecure: true, Project: "default", DialOptions: srv.Dial(t)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx := context.Background()
	f, err := Parse([]byte("permissions: [a.read]\nroles:\n  r: {permissions: [a.read]}\ngrants:\n  - {principal: u, resource: /x, roles: [r]}\n"))
	if err != nil {
		t.Fatal(err)
	}
	f.Project = "default"
	state, err := Fetch(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := ComputePlan(f, state, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(ctx, c, plan, state, nil); err != nil {
		t.Fatal(err)
	}
	res, err := c.Check(ctx, "u", []string{"/x/y"}, []string{"a.read"})
	if err != nil || !res.Allowed {
		t.Fatalf("check after apply: %+v %v", res, err)
	}
	state, _ = Fetch(ctx, c)
	exported, err := state.Export("default")
	if err != nil || len(exported.Grants) != 1 || exported.Grants[0].Roles[0] != "r" {
		t.Fatalf("export: %+v %v", exported, err)
	}
}

func TestExampleFileParses(t *testing.T) {
	data, err := os.ReadFile("../../examples/permio.yaml")
	if err != nil {
		t.Fatal(err)
	}
	f, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := ComputePlan(f, &State{Permissions: map[string]permio.Permission{}, Roles: map[string]permio.Role{}, Groups: map[string]GroupState{}, Grants: map[string]permio.Grant{}}, Options{Prune: true})
	if err != nil || plan.Summary.Create == 0 || plan.Summary.Delete != 0 {
		t.Fatalf("plan: %+v %v", plan, err)
	}
}
