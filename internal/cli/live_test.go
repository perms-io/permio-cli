package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// Live tests run against a real perms.io API when PERMIO_TEST_API_KEY and
// PERMIO_TEST_API_URL are set (PERMIO_TEST_PROJECT defaults to "default").
// They only read, unless PERMIO_TEST_WRITE=1 and the key has full access; the
// write test creates uniquely named objects and deletes them again.
func liveApp(t *testing.T) func(args ...string) result {
	t.Helper()
	key, url := os.Getenv("PERMIO_TEST_API_KEY"), os.Getenv("PERMIO_TEST_API_URL")
	if key == "" || url == "" {
		t.Skip("set PERMIO_TEST_API_KEY and PERMIO_TEST_API_URL to run live tests")
	}
	project := os.Getenv("PERMIO_TEST_PROJECT")
	if project == "" {
		project = "default"
	}
	env := map[string]string{
		"PERMIO_API_KEY": key, "PERMIO_API_URL": url, "PERMIO_PROJECT": project,
		"PERMIO_CONFIG": t.TempDir() + "/config.yaml",
	}
	return func(args ...string) result {
		var out, errb bytes.Buffer
		a := &App{Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb, Getenv: func(k string) string { return env[k] }, StdinIsTTY: func() bool { return false }}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		code := a.Run(ctx, args)
		return result{out.String(), errb.String(), code}
	}
}

func TestLiveRead(t *testing.T) {
	run := liveApp(t)
	if r := run("permissions", "list", "--json"); r.code != 0 {
		t.Fatalf("permissions list: %+v", r)
	}
	if r := run("check", "permio-cli-live-test-nobody", "/permio-cli-live-test", "permio.cli.nothing"); r.code != ExitDenied {
		t.Fatalf("check should be denied: %+v", r)
	}
	if r := run("export"); r.code != 0 {
		t.Fatalf("export: %+v", r)
	}
}

func TestLiveWrite(t *testing.T) {
	run := liveApp(t)
	if os.Getenv("PERMIO_TEST_WRITE") != "1" {
		t.Skip("set PERMIO_TEST_WRITE=1 (with a full-access key) to run the live write test")
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	perm, role, group := "clitest.read"+suffix, "clitest-role-"+suffix, "clitest-"+suffix
	user, res := "clitest-user-"+suffix, "/clitest/"+suffix
	t.Cleanup(func() {
		run("groups", "delete", group)
		run("grants", "remove", "--principal", user, "--resource", res, "--all")
		run("roles", "delete", role)
		run("permissions", "delete", perm)
	})
	must := func(args ...string) {
		t.Helper()
		if r := run(args...); r.code != 0 {
			t.Fatalf("permio %s: %+v", strings.Join(args, " "), r)
		}
	}
	must("permissions", "create", perm)
	// Create is an upsert: a new description replaces the stored one.
	if r := run("permissions", "create", perm, "--description", "different", "--json"); r.code != 0 || !strings.Contains(r.stdout, `"different"`) {
		t.Fatalf("permission upsert: %+v", r)
	}
	must("permissions", "delete", perm+".missing")
	must("roles", "create", role, "-p", perm)
	must("groups", "create", group, "--member", user)
	must("grants", "add", "--principal", "group:"+group, "--resource", res, "-r", role)
	must("check", user, res+"/child", perm)
	must("grants", "remove", "--principal", "group:"+group, "--resource", res, "-r", role)
	if r := run("check", user, res+"/child", perm); r.code != ExitDenied {
		t.Fatalf("check after revoke: %+v", r)
	}
}
