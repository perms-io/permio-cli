package cli

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/PrivateJAR/permio-cli/pkg/configsync"
)

const sampleConfig = `
project: default
permissions:
  - document.read
  - { name: document.edit, description: Edit documents }
roles:
  editor: { description: Can edit, permissions: [document.read, document.edit] }
  viewer: { permissions: [document.read] }
groups:
  design: { description: Design team, members: [user_1, user_2] }
grants:
  - { principal: group:design, resource: /projects/123, roles: [editor] }
  - { principal: user_9, resource: /projects/123/docs, roles: [viewer], permissions: [document.edit] }
`

func (h *harness) writeFile(name, content string) string {
	h.t.Helper()
	p := filepath.Join(h.t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		h.t.Fatal(err)
	}
	return p
}

func TestPlanApplyOrderAndIdempotency(t *testing.T) {
	h := newHarness(t)
	h.srv.MaxPageSize = 1
	file := h.writeFile("permio.yaml", sampleConfig)

	plan := decode[configsync.Plan](t, h.must("plan", "-f", file, "--json").stdout)
	if plan.Project != "default" || plan.Summary != (configsync.Summary{Create: 9}) {
		t.Fatalf("plan summary: %+v", plan.Summary)
	}
	var kinds []string
	for _, c := range plan.Changes {
		kinds = append(kinds, string(c.Action)+" "+string(c.Kind)+" "+c.Name)
	}
	want := []string{
		"create permission document.read", // file order
		"create permission document.edit",
		"create role editor",
		"create role viewer",
		"create group design",
		"create member design/user_1",
		"create member design/user_2",
		"create grant group:design /projects/123",
		"create grant user_9 /projects/123/docs",
	}
	if !reflect.DeepEqual(kinds, want) {
		t.Fatalf("plan order:\n got %q\nwant %q", kinds, want)
	}
	// plan changes nothing.
	if calls := h.srv.Calls(); len(calls) != 0 {
		t.Fatalf("plan made writes: %v", calls)
	}

	// Human plan output.
	text := h.must("plan", "-f", file).stdout
	for _, s := range []string{"+ permission document.edit", "+ role editor", "+ member user_1 in group design", "+ grant group:design on /projects/123", "Plan: 9 to create, 0 to update, 0 to delete."} {
		if !strings.Contains(text, s) {
			t.Fatalf("plan text lacks %q:\n%s", s, text)
		}
	}

	// apply in dependency order.
	res := decode[applyOutput](t, h.must("apply", "-f", file, "--yes", "--json").stdout)
	if res.Summary.Create != 9 || len(res.Applied) != 9 {
		t.Fatalf("apply: %+v", res.Summary)
	}
	calls := h.srv.Calls()
	order := []string{"CreatePermission", "CreateRole", "CreateGroup", "AddGroupMembers", "Grant"}
	last := -1
	for _, prefix := range order {
		idx := -1
		for i, c := range calls {
			if strings.HasPrefix(c, prefix) {
				idx = i
				break
			}
		}
		if idx <= last {
			t.Fatalf("%s out of order in %v", prefix, calls)
		}
		last = idx
	}
	// Members of one group are added in one call.
	n := 0
	for _, c := range calls {
		if strings.HasPrefix(c, "AddGroupMembers") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("member adds should be batched: %v", calls)
	}

	// The result is what the file says.
	if r := h.run("check", "user_2", "/projects/123/x", "document.edit"); r.code != 0 {
		t.Fatalf("group grant not effective: %+v", r)
	}

	// Idempotent: plan is empty and apply makes no calls.
	h.srv.ResetCalls()
	plan = decode[configsync.Plan](t, h.must("plan", "-f", file, "--json").stdout)
	if !plan.Empty() || plan.Changes == nil {
		t.Fatalf("second plan not empty: %+v", plan.Changes)
	}
	if out := h.must("apply", "-f", file, "--yes").stdout; !strings.Contains(out, "No changes") {
		t.Fatalf("second apply: %s", out)
	}
	if calls := h.srv.Calls(); len(calls) != 0 {
		t.Fatalf("second apply made writes: %v", calls)
	}
}

func TestApplyUpdatesAndPrune(t *testing.T) {
	h := newHarness(t)
	file := h.writeFile("permio.yaml", sampleConfig)
	h.must("apply", "-f", file, "--yes")

	// Out-of-band objects: kept without --prune, deleted with it.
	h.must("permissions", "create", "legacy.perm")
	h.must("roles", "create", "legacy", "-p", "legacy.perm")
	h.must("groups", "create", "old-team", "--member", "x")
	h.must("grants", "add", "--principal", "stranger", "--resource", "/projects/1", "-r", "legacy")
	h.must("grants", "add", "--principal", "user_9", "--resource", "/projects/123/docs", "-r", "editor") // extra role on a listed pair

	updated := strings.NewReplacer(
		"description: Edit documents", "description: Edit any document",
		"members: [user_1, user_2]", "members: [user_2, user_3]",
		"permissions: [document.read]", "permissions: [document.read, document.edit]",
	).Replace(sampleConfig)
	file = h.writeFile("permio.yaml", updated)

	plan := decode[configsync.Plan](t, h.must("plan", "-f", file, "--json").stdout)
	got := map[string]configsync.Change{}
	for _, c := range plan.Changes {
		got[string(c.Action)+" "+string(c.Kind)+" "+c.Name] = c
	}
	if c, ok := got["update permission document.edit"]; !ok || c.Description.To != "Edit any document" {
		t.Fatalf("permission update: %+v", plan.Changes)
	}
	if c, ok := got["update role viewer"]; !ok || !reflect.DeepEqual(c.AddPermissions, []string{"document.edit"}) {
		t.Fatalf("role update: %+v", plan.Changes)
	}
	if _, ok := got["create member design/user_3"]; !ok {
		t.Fatalf("member add: %+v", plan.Changes)
	}
	if _, ok := got["delete member design/user_1"]; !ok {
		t.Fatalf("member remove (full list, no --prune needed): %+v", plan.Changes)
	}
	if c, ok := got["update grant user_9 /projects/123/docs"]; !ok || !reflect.DeepEqual(c.RemoveRoles, []string{"editor"}) {
		t.Fatalf("grant pair is the full set: %+v", plan.Changes)
	}
	for k := range got {
		if strings.Contains(k, "legacy") || strings.Contains(k, "old-team") || strings.Contains(k, "stranger") {
			t.Fatalf("without --prune nothing outside the file is touched: %s", k)
		}
	}
	h.must("apply", "-f", file, "--yes")

	// --prune deletes the rest, in reverse dependency order.
	h.srv.ResetCalls()
	plan = decode[configsync.Plan](t, h.must("plan", "-f", file, "--prune", "--json").stdout)
	var names []string
	for _, c := range plan.Changes {
		names = append(names, string(c.Action)+" "+string(c.Kind)+" "+c.Name)
	}
	want := []string{
		"delete grant stranger /projects/1",
		"delete group old-team",
		"delete role legacy",
		"delete permission legacy.perm",
	}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("prune plan:\n got %q\nwant %q", names, want)
	}
	h.must("apply", "-f", file, "--prune", "--yes")
	if calls := h.srv.Calls(); len(calls) != 4 || !strings.HasPrefix(calls[0], "Revoke stranger") || !strings.HasPrefix(calls[3], "DeletePermission legacy.perm") {
		t.Fatalf("prune calls: %v", calls)
	}
	plan = decode[configsync.Plan](t, h.must("plan", "-f", file, "--prune", "--json").stdout)
	if !plan.Empty() {
		t.Fatalf("not converged: %+v", plan.Changes)
	}
}

func TestApplyConfirmation(t *testing.T) {
	h := newHarness(t)
	file := h.writeFile("permio.yaml", "permissions: [a.b]\n")

	// Not a TTY and no --yes: refuse, change nothing.
	r := h.runIO("", false, "apply", "-f", file)
	if r.code != ExitError || !strings.Contains(r.stderr, "--yes") || len(h.srv.Calls()) != 0 {
		t.Fatalf("non-tty: %+v", r)
	}
	// TTY, answer no.
	r = h.runIO("no\n", true, "apply", "-f", file)
	if r.code != ExitError || len(h.srv.Calls()) != 0 || !strings.Contains(r.stderr, "Cancelled") {
		t.Fatalf("tty no: %+v %v", r, h.srv.Calls())
	}
	// TTY, answer yes.
	r = h.runIO("yes\n", true, "apply", "-f", file)
	if r.code != 0 || len(h.srv.Calls()) != 1 {
		t.Fatalf("tty yes: %+v %v", r, h.srv.Calls())
	}
	// File from stdin requires --yes.
	if r := h.runIO("permissions: [a.b]\n", true, "apply", "-f", "-"); r.code != ExitError {
		t.Fatalf("stdin file: %+v", r)
	}
	h.must("apply", "-f", file, "--yes", "--json")
}

func TestExportRoundTrip(t *testing.T) {
	h := newHarness(t)
	h.srv.MaxPageSize = 2
	h.must("apply", "-f", h.writeFile("permio.yaml", sampleConfig), "--yes")
	h.must("permissions", "create", "extra.perm", "--description", "Out of band")
	h.must("grants", "add", "--principal", "zed", "--resource", "/z/_/q", "-p", "extra.perm")

	exported := h.must("export").stdout
	if !strings.HasPrefix(exported, "# yaml-language-server: $schema=") {
		t.Fatalf("schema comment missing:\n%s", exported)
	}
	f, err := configsync.Parse([]byte(exported))
	if err != nil {
		t.Fatalf("export does not parse: %v\n%s", err, exported)
	}
	if f.Project != "default" || len(f.Permissions) != 3 || len(f.Grants) != 3 || *f.Groups["design"].Members == nil {
		t.Fatalf("export content:\n%s", exported)
	}
	// Planning the export, even with --prune, shows no changes.
	file := h.writeFile("exported.yaml", exported)
	plan := decode[configsync.Plan](t, h.must("plan", "-f", file, "--prune", "--json").stdout)
	if !plan.Empty() {
		t.Fatalf("round trip not clean: %+v", plan.Changes)
	}
	// Export to a file, and as JSON.
	out := filepath.Join(t.TempDir(), "out.yaml")
	h.must("export", "-o", out)
	if data, _ := os.ReadFile(out); string(data) != exported {
		t.Fatalf("export -o differs")
	}
	j := decode[map[string]any](t, h.must("export", "--json").stdout)
	if j["project"] != "default" {
		t.Fatalf("export json: %v", j)
	}
}

func TestPlanErrors(t *testing.T) {
	h := newHarness(t)
	cases := map[string]string{
		"unknown field":    "permisions: [a]\n",
		"bad name":         "permissions: ['has space']\n",
		"duplicate pair":   "permissions: [a]\ngrants:\n  - {principal: u, resource: /x, permissions: [a]}\n  - {principal: u, resource: /x, permissions: [a]}\n",
		"missing perm":     "roles:\n  r: {permissions: [nope]}\n",
		"missing role":     "grants:\n  - {principal: u, resource: /x, roles: [ghost]}\n",
		"missing group":    "grants:\n  - {principal: group:ghost, resource: /x}\n",
		"nested group":     "groups:\n  g: {members: ['group:h']}\n",
		"bad uri":          "grants:\n  - {principal: u, resource: x}\n",
		"project conflict": "project: other\n",
	}
	h.env["PERMIO_PROJECT"] = "default"
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			r := h.run("plan", "-f", h.writeFile("p.yaml", content))
			if r.code != ExitError {
				t.Fatalf("exit %d, want 2\n%s%s", r.code, r.stdout, r.stderr)
			}
		})
	}
	// With --prune, references to objects outside the file are errors too.
	h.must("permissions", "create", "kept")
	content := "roles:\n  r: {permissions: [kept]}\n"
	h.must("plan", "-f", h.writeFile("p.yaml", content))
	if r := h.run("plan", "-f", h.writeFile("p.yaml", content), "--prune"); r.code != ExitError || !strings.Contains(r.stderr, "--prune would delete it") {
		t.Fatalf("prune reference: %+v", r)
	}
}

func TestApplyStopsOnFailure(t *testing.T) {
	h := newHarness(t)
	file := h.writeFile("permio.yaml", sampleConfig)
	r := h.run("apply", "-f", file, "--yes", "--api-key", h.checkKey, "--json")
	if r.code != ExitPermission {
		t.Fatalf("check-only apply: %+v", r)
	}
	out := decode[applyOutput](t, r.stdout)
	if len(out.Applied) != 0 || len(out.Plan.Changes) != 9 {
		t.Fatalf("partial result: %+v", out)
	}
}
