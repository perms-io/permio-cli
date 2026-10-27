package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	"github.com/PrivateJAR/permio-cli/pkg/apikey"
	"github.com/PrivateJAR/permio-cli/pkg/fakeserver"
)

func mustKey(t testing.TB, body string) string {
	t.Helper()
	k, err := apikey.WithChecksum(body)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

type harness struct {
	t         *testing.T
	srv       *fakeserver.Server
	dial      []grpc.DialOption
	fullKey   string
	checkKey  string
	otherKey  string // full access, but for project "other"
	env       map[string]string
	configDir string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{
		t:         t,
		srv:       fakeserver.New(),
		fullKey:   mustKey(t, "FULLaccessKEY0123456789abcdefghi"),
		checkKey:  mustKey(t, "CHECKonlyKEY0123456789abcdefghij"),
		otherKey:  mustKey(t, "OTHERprojectKEY0123456789abcdefg"),
		configDir: t.TempDir(),
	}
	h.srv.AddKey(h.fullKey, "default", true)
	h.srv.AddKey(h.checkKey, "default", false)
	h.srv.AddKey(h.otherKey, "other", true)
	h.dial = h.srv.Dial(t)
	h.env = map[string]string{
		"PERMIO_API_KEY": h.fullKey,
		"PERMIO_API_URL": "http://localhost:1", // the bufconn dialer ignores the address
		"PERMIO_CONFIG":  filepath.Join(h.configDir, "config.yaml"),
	}
	return h
}

type result struct {
	stdout, stderr string
	code           int
}

func (h *harness) runIO(stdin string, tty bool, args ...string) result {
	h.t.Helper()
	var out, errb bytes.Buffer
	a := &App{
		Stdin:       strings.NewReader(stdin),
		Stdout:      &out,
		Stderr:      &errb,
		Getenv:      func(k string) string { return h.env[k] },
		StdinIsTTY:  func() bool { return tty },
		DialOptions: h.dial,
	}
	code := a.Run(context.Background(), args)
	return result{out.String(), errb.String(), code}
}

func (h *harness) run(args ...string) result {
	h.t.Helper()
	return h.runIO("", false, args...)
}

// must runs a command and fails the test unless it exits 0.
func (h *harness) must(args ...string) result {
	h.t.Helper()
	r := h.run(args...)
	if r.code != 0 {
		h.t.Fatalf("permio %s: exit %d\nstdout: %s\nstderr: %s", strings.Join(args, " "), r.code, r.stdout, r.stderr)
	}
	return r
}

func decode[T any](t *testing.T, s string) T {
	t.Helper()
	var v T
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, s)
	}
	return v
}

// seed creates permissions document.read/edit, role editor (both) and viewer (read).
func (h *harness) seed() {
	h.must("permissions", "create", "document.read", "document.edit")
	h.must("roles", "create", "editor", "-p", "document.read,document.edit")
	h.must("roles", "create", "viewer", "-p", "document.read")
}

func TestCheckExitCodes(t *testing.T) {
	h := newHarness(t)
	h.seed()
	h.must("grants", "add", "--principal", "alice", "--resource", "/docs", "--role", "viewer")

	// Inherited from /docs: allowed.
	if r := h.run("check", "alice", "/docs/42", "document.read"); r.code != ExitOK || !strings.Contains(r.stdout, "allowed") {
		t.Fatalf("allowed: %+v", r)
	}
	// Missing document.edit: denied, exit 1, --explain lists it.
	r := h.run("check", "alice", "/docs/42", "document.read", "document.edit", "--explain")
	if r.code != ExitDenied || !strings.Contains(r.stdout, "missing on /docs/42: document.edit") {
		t.Fatalf("denied: %+v", r)
	}
	// Not under /docs: denied.
	if r := h.run("check", "alice", "/other", "document.read", "-q"); r.code != ExitDenied || r.stdout != "" {
		t.Fatalf("quiet denied: %+v", r)
	}
	// Invalid URI: usage/API error, exit 2.
	if r := h.run("check", "alice", "docs", "document.read"); r.code != ExitError {
		t.Fatalf("invalid uri: %+v", r)
	}
	// Too few args: exit 2.
	if r := h.run("check", "alice"); r.code != ExitError {
		t.Fatalf("usage: %+v", r)
	}
	// Malformed key: exit 3, before any request.
	if r := h.run("check", "alice", "/docs", "document.read", "--api-key", "perms_short"); r.code != ExitAuth {
		t.Fatalf("malformed key: %+v", r)
	}
	// Well-formed but unknown key: exit 3 from the API.
	unknown := mustKey(t, "UNKNOWNkey0123456789abcdefghijkl")
	if r := h.run("check", "alice", "/docs", "document.read", "--api-key", unknown); r.code != ExitAuth {
		t.Fatalf("unknown key: %+v", r)
	}
	// Key for another project: permission denied for the key, exit 4.
	if r := h.run("check", "alice", "/docs", "document.read", "--api-key", h.otherKey); r.code != ExitPermission || !strings.Contains(r.stderr, "missing permission.check") {
		t.Fatalf("other project: %+v", r)
	}
	// Check-only key can check but not write.
	if r := h.run("check", "alice", "/docs", "document.read", "--api-key", h.checkKey); r.code != ExitOK {
		t.Fatalf("check-only check: %+v", r)
	}
	if r := h.run("permissions", "create", "x.y", "--api-key", h.checkKey); r.code != ExitPermission {
		t.Fatalf("check-only write: %+v", r)
	}
}

func TestCheckJSONAndGroupsAndWildcards(t *testing.T) {
	h := newHarness(t)
	h.seed()
	h.must("groups", "create", "design", "--member", "bob")
	h.must("grants", "add", "--principal", "group:design", "--resource", "/tenants/acme", "--role", "editor")
	h.must("grants", "add", "--principal", "carol", "--resource", "/tenants/_/docs", "--permission", "document.read")

	r := h.run("check", "bob", "/tenants/acme/docs/1", "document.edit", "--json")
	got := decode[map[string]any](t, r.stdout)
	if r.code != 0 || got["allowed"] != true || got["principal"] != "bob" || got["resource"] != "/tenants/acme/docs/1" {
		t.Fatalf("group check: %d %v", r.code, got)
	}
	if missing, ok := got["missing"].([]any); !ok || len(missing) != 0 {
		t.Fatalf("missing should be an empty array: %v", got["missing"])
	}

	// "_" matches one segment.
	if r := h.run("check", "carol", "/tenants/globex/docs/9", "document.read"); r.code != ExitOK {
		t.Fatalf("wildcard: %+v", r)
	}
	r = h.run("check", "carol", "/tenants/globex/other", "document.read", "--json")
	got = decode[map[string]any](t, r.stdout)
	if r.code != ExitDenied || got["allowed"] != false {
		t.Fatalf("wildcard denied: %d %v", r.code, got)
	}
	missing := got["missing"].([]any)[0].(map[string]any)
	if missing["resource"] != "/tenants/globex/other" || !reflect.DeepEqual(missing["permissions"], []any{"document.read"}) {
		t.Fatalf("missing: %v", missing)
	}
}

func TestCheckBatch(t *testing.T) {
	h := newHarness(t)
	h.seed()
	h.must("grants", "add", "--principal", "alice", "--resource", "/docs/1", "--role", "viewer")
	r := h.runIO("/docs/1\n# comment\n\n/docs/2\n", false, "check", "batch", "alice", "-p", "document.read", "--json")
	if r.code != ExitDenied {
		t.Fatalf("exit %d: %s %s", r.code, r.stdout, r.stderr)
	}
	out := decode[batchOutput](t, r.stdout)
	if out.AllAllowed || out.Allowed != 1 || out.Denied != 1 || len(out.Results) != 2 || !out.Results[0].Allowed || out.Results[1].Missing[0] != "document.read" {
		t.Fatalf("batch: %+v", out)
	}
	if r := h.run("check", "batch", "alice", "-p", "document.read", "/docs/1"); r.code != ExitOK {
		t.Fatalf("all allowed: %+v", r)
	}
}

func TestJSONShapes(t *testing.T) {
	h := newHarness(t)
	h.srv.MaxPageSize = 2 // exercise pagination
	h.must("permissions", "create", "a.one", "a.two", "a.three", "--description", "d")
	h.seed()

	perms := decode[map[string][]map[string]string](t, h.must("permissions", "list", "--json").stdout)
	if len(perms["permissions"]) != 5 || perms["permissions"][0]["name"] != "a.one" || perms["permissions"][0]["description"] != "d" {
		t.Fatalf("permissions: %v", perms)
	}

	role := decode[map[string]any](t, h.must("roles", "get", "editor", "--json").stdout)
	for _, k := range []string{"id", "name", "description", "permissions"} {
		if _, ok := role[k]; !ok {
			t.Fatalf("role JSON lacks %q: %v", k, role)
		}
	}

	h.must("grants", "add", "--principal", "alice", "--resource", "/docs", "--role", "editor", "--permission", "a.one")
	grants := decode[map[string][]map[string]any](t, h.must("grants", "list", "--principal", "alice", "--json").stdout)
	g := grants["grants"][0]
	if g["principal"] != "alice" || g["resource"] != "/docs" || !reflect.DeepEqual(g["permissions"], []any{"a.one"}) {
		t.Fatalf("grant: %v", g)
	}
	if roles := g["roles"].([]any); roles[0].(map[string]any)["name"] != "editor" {
		t.Fatalf("grant roles: %v", g["roles"])
	}
	// By resource, and all grants, give the same shape.
	byRes := decode[map[string][]map[string]any](t, h.must("grants", "list", "--resource", "/docs", "--json").stdout)
	all := decode[map[string][]map[string]any](t, h.must("grants", "list", "--json").stdout)
	if !reflect.DeepEqual(byRes, grants) || !reflect.DeepEqual(all, grants) {
		t.Fatalf("grant listings differ:\n%v\n%v\n%v", grants, byRes, all)
	}

	// Errors are JSON on stderr with the exit code.
	r := h.run("roles", "get", "nope", "--json")
	e := decode[map[string]map[string]any](t, r.stderr)["error"]
	if r.code != ExitError || e["kind"] != "not_found" || e["exit_code"] != float64(2) || r.stdout != "" {
		t.Fatalf("error JSON: %d %v", r.code, e)
	}
	r = h.run("permissions", "list", "--json", "--api-key", "garbage")
	e = decode[map[string]map[string]any](t, r.stderr)["error"]
	if r.code != ExitAuth || e["kind"] != "auth" {
		t.Fatalf("auth error JSON: %d %v", r.code, e)
	}

	v := decode[map[string]string](t, h.must("version", "--json").stdout)
	if _, ok := v["version"]; !ok {
		t.Fatalf("version: %v", v)
	}
}

func TestRolesUpdate(t *testing.T) {
	h := newHarness(t)
	h.seed()
	h.must("permissions", "create", "document.delete")
	r := decode[map[string]any](t, h.must("roles", "update", "viewer", "--add-permission", "document.edit,document.delete", "--remove-permission", "document.read", "--json").stdout)
	if !reflect.DeepEqual(r["permissions"], []any{"document.delete", "document.edit"}) || r["name"] != "viewer" {
		t.Fatalf("update: %v", r)
	}
	id := r["id"].(string)
	h.must("roles", "update", id, "--name", "reviewer", "--description", "Reviews")
	r = decode[map[string]any](t, h.must("roles", "get", "reviewer", "--json").stdout)
	if r["id"] != id || r["description"] != "Reviews" {
		t.Fatalf("rename: %v", r)
	}
	if res := h.run("roles", "update", "reviewer"); res.code != ExitError {
		t.Fatalf("no-op update should be a usage error: %+v", res)
	}
	h.must("roles", "delete", "reviewer")
	if res := h.run("roles", "get", id); res.code != ExitError {
		t.Fatalf("deleted role still found: %+v", res)
	}
}

func TestGrantsRemoveAndGroups(t *testing.T) {
	h := newHarness(t)
	h.seed()
	h.must("grants", "add", "--principal", "alice", "--resource", "/docs", "-r", "editor", "-p", "document.read")
	h.must("grants", "remove", "--principal", "alice", "--resource", "/docs", "-r", "editor")
	out := decode[map[string][]map[string]any](t, h.must("grants", "list", "--principal", "alice", "--json").stdout)
	if len(out["grants"]) != 1 || len(out["grants"][0]["roles"].([]any)) != 0 {
		t.Fatalf("after remove: %v", out)
	}
	h.must("grants", "remove", "--principal", "alice", "--resource", "/docs", "--all")
	out = decode[map[string][]map[string]any](t, h.must("grants", "list", "--principal", "alice", "--json").stdout)
	if len(out["grants"]) != 0 {
		t.Fatalf("after remove --all: %v", out)
	}

	h.must("groups", "create", "ops", "--description", "Ops")
	add := decode[map[string]any](t, h.must("groups", "members", "add", "ops", "u1", "u2", "--json").stdout)
	if !reflect.DeepEqual(add["added"], []any{"u1", "u2"}) {
		t.Fatalf("members add: %v", add)
	}
	h.must("groups", "members", "remove", "ops", "u1")
	g := decode[map[string]any](t, h.must("groups", "get", "ops", "--json").stdout)
	if !reflect.DeepEqual(g["members"], []any{"u2"}) || g["principal_id"] != "group:ops" || g["description"] != "Ops" {
		t.Fatalf("group: %v", g)
	}
	if r := h.run("groups", "members", "add", "ops", "group:other"); r.code != ExitError {
		t.Fatalf("nested group: %+v", r)
	}
}

func TestAccessCommands(t *testing.T) {
	h := newHarness(t)
	h.seed()
	h.must("groups", "create", "design", "--member", "bob")
	h.must("grants", "add", "--principal", "alice", "--resource", "/docs/1", "-r", "viewer")
	h.must("grants", "add", "--principal", "alice", "--resource", "/docs/_/public", "-r", "viewer")
	h.must("grants", "add", "--principal", "group:design", "--resource", "/docs", "-r", "editor")

	r := h.run("access", "list", "--principal", "alice", "--permission", "document.read", "--under", "/docs", "--allows", "/docs/1/x,/docs/9/public,/docs/2", "--json")
	out := decode[map[string]any](t, r.stdout)
	if r.code != ExitDenied || out["covers_all"] != false {
		t.Fatalf("access list: %d %v", r.code, out)
	}
	if !reflect.DeepEqual(out["prefixes"], []any{"/docs/1"}) || !reflect.DeepEqual(out["patterns"], []any{"/docs/_/public"}) {
		t.Fatalf("scopes: %v", out)
	}
	allows := out["allows"].([]any)
	if allows[0].(map[string]any)["allowed"] != true || allows[1].(map[string]any)["allowed"] != true || allows[2].(map[string]any)["allowed"] != false {
		t.Fatalf("allows: %v", allows)
	}
	r = h.run("access", "list", "--principal", "bob", "--permission", "document.edit", "--under", "/docs/7")
	if r.code != 0 || !strings.Contains(r.stdout, "on all of /docs/7") {
		t.Fatalf("covers all: %+v", r)
	}

	who := decode[map[string]any](t, h.must("access", "who", "--resource", "/docs/1", "--permission", "document.edit", "--expand-groups", "--json").stdout)
	ps := who["principals"].([]any)
	if len(ps) != 2 {
		t.Fatalf("who: %v", ps)
	}
	first, second := ps[0].(map[string]any), ps[1].(map[string]any)
	if first["principal"] != "bob" || first["via_group"] != "design" || second["principal"] != "group:design" || second["is_group"] != true {
		t.Fatalf("who entries: %v", ps)
	}
}

func TestRetriesOnlyForReads(t *testing.T) {
	h := newHarness(t)
	h.seed()
	h.srv.FailOnce("Check", codes.Unavailable)
	if r := h.run("check", "x", "/a", "document.read"); r.code != ExitDenied {
		t.Fatalf("check should be retried: %+v", r)
	}
	h.srv.FailOnce("CreatePermission", codes.Unavailable)
	if r := h.run("permissions", "create", "z.z"); r.code != ExitError {
		t.Fatalf("create should not be retried: %+v", r)
	}
}

func TestConfigPrecedenceAndProfiles(t *testing.T) {
	h := newHarness(t)
	delete(h.env, "PERMIO_API_KEY")

	// No key anywhere: auth error.
	if r := h.run("permissions", "list"); r.code != ExitAuth {
		t.Fatalf("no key: %+v", r)
	}
	// Malformed keys are rejected when saved.
	if r := h.run("config", "set", "api-key", "perms_nope"); r.code != ExitAuth {
		t.Fatalf("bad key saved: %+v", r)
	}
	// Profile holds the check-only key; key read from stdin.
	if r := h.runIO(h.checkKey+"\n", false, "config", "set", "api-key", "-"); r.code != 0 {
		t.Fatalf("config set: %+v", r)
	}
	st, err := os.Stat(h.env["PERMIO_CONFIG"])
	if err != nil || (runtime.GOOS != "windows" && st.Mode().Perm() != 0o600) {
		t.Fatalf("config file mode: %v %v", st, err)
	}
	// Profile: check-only key, writes are denied.
	if r := h.run("permissions", "create", "p.one"); r.code != ExitPermission {
		t.Fatalf("profile key should be check-only: %+v", r)
	}
	// Env beats profile.
	h.env["PERMIO_API_KEY"] = h.fullKey
	h.must("permissions", "create", "p.one")
	// Flag beats env.
	if r := h.run("permissions", "create", "p.two", "--api-key", h.checkKey); r.code != ExitPermission {
		t.Fatalf("flag should beat env: %+v", r)
	}
	// Project: profile < env < flag.
	h.must("config", "set", "project", "other")
	delete(h.env, "PERMIO_API_KEY")
	if r := h.run("permissions", "list", "--api-key", h.fullKey); r.code != ExitPermission {
		t.Fatalf("profile project should be used: %+v", r)
	}
	h.env["PERMIO_PROJECT"] = "default"
	h.must("permissions", "list", "--api-key", h.fullKey)
	if r := h.run("permissions", "list", "--api-key", h.fullKey, "--project", "other"); r.code != ExitPermission {
		t.Fatalf("flag project should beat env: %+v", r)
	}

	// Named profiles.
	h.must("config", "set", "--profile", "ops", "api-key", h.otherKey)
	h.must("config", "set", "--profile", "ops", "project", "other")
	delete(h.env, "PERMIO_PROJECT")
	h.must("permissions", "list", "--profile", "ops")
	if r := h.run("permissions", "list", "--profile", "missing"); r.code != ExitError {
		t.Fatalf("missing profile: %+v", r)
	}
	h.must("config", "use", "ops")
	list := decode[map[string]any](t, h.must("config", "list", "--json").stdout)
	if list["current_profile"] != "ops" || strings.Contains(h.must("config", "list").stdout, h.otherKey) {
		t.Fatalf("config list: %v", list)
	}
	eff := list["effective"].(map[string]any)
	if eff["project"] != "other" || eff["api_key_source"] != "profile" {
		t.Fatalf("effective: %v", eff)
	}
}

// Creates are upserts and deletes are idempotent, as in the API; only a
// rename onto a name in use is a clash.
func TestCreateUpsertsAndIdempotentDelete(t *testing.T) {
	h := newHarness(t)
	h.seed()

	// A different description replaces the stored one.
	r := h.must("permissions", "create", "document.read", "--description", "other", "--json")
	if !strings.Contains(r.stdout, `"other"`) {
		t.Fatalf("permission upsert: %+v", r)
	}
	// No description keeps it.
	if r := h.must("permissions", "get", "document.read", "--json"); !strings.Contains(r.stdout, `"other"`) {
		t.Fatalf("permission after create without description: %+v", r)
	}
	if r := h.run("permissions", "update", "document.edit", "--rename", "document.read", "--json"); r.code != ExitError || !strings.Contains(r.stderr, `"already_exists"`) || !strings.Contains(r.stderr, "already exists") {
		t.Fatalf("permission rename clash: %+v", r)
	}

	// Creating a role that exists returns it, with a new permission list.
	r = h.must("roles", "create", "viewer", "-p", "document.edit", "--json")
	if !strings.Contains(r.stdout, "document.edit") || strings.Contains(r.stdout, `"document.read"`) {
		t.Fatalf("role upsert: %+v", r)
	}
	h.must("roles", "create", "viewer", "-p", "document.edit")

	h.must("permissions", "delete", "nope.none")
	h.must("permissions", "create", "temp.perm")
	h.must("permissions", "delete", "temp.perm")
	if r := h.run("permissions", "get", "temp.perm"); r.code != ExitError {
		t.Fatalf("permission should be gone: %+v", r)
	}
}

// The SDK takes at most 100 principals per membership write; the CLI splits
// longer lists.
func TestGroupMembersOverOneHundred(t *testing.T) {
	h := newHarness(t)
	h.seed()
	h.must("groups", "create", "big")
	args := []string{"groups", "members", "add", "big", "user_0"}
	for i := range 250 {
		args = append(args, fmt.Sprintf("user_%d", i))
	}
	r := h.must(append(args, "--json")...)
	if res := decode[map[string]any](t, r.stdout); len(res["added"].([]any)) != 250 || len(res["already_members"].([]any)) != 0 {
		t.Fatalf("add: %v", res)
	}
	args[2] = "remove"
	r = h.must(append(args, "--json")...)
	if res := decode[map[string]any](t, r.stdout); len(res["removed"].([]any)) != 250 {
		t.Fatalf("remove: %v", res)
	}
}
