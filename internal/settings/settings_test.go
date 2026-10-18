package settings

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestResolvePrecedence(t *testing.T) {
	f := &File{
		CurrentProfile: "work",
		Profiles: map[string]*Profile{
			"work":  {APIKey: "profile-key", APIURL: "dev", Project: "profile-project"},
			"other": {APIKey: "other-key"},
		},
	}

	// Profile only.
	r, err := Resolve(f, Overrides{}, env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if r.APIKey != "profile-key" || r.APIKeySource != SourceProfile || r.Project != "profile-project" || r.APIURL != "dev" {
		t.Fatalf("profile: %+v", r)
	}

	// Env beats profile.
	r, _ = Resolve(f, Overrides{}, env(map[string]string{EnvAPIKey: "env-key", EnvProject: "env-project"}))
	if r.APIKey != "env-key" || r.APIKeySource != SourceEnv || r.Project != "env-project" || r.APIURL != "dev" {
		t.Fatalf("env: %+v", r)
	}

	// Flag beats env.
	r, _ = Resolve(f, Overrides{APIKey: "flag-key"}, env(map[string]string{EnvAPIKey: "env-key"}))
	if r.APIKey != "flag-key" || r.APIKeySource != SourceFlag {
		t.Fatalf("flag: %+v", r)
	}

	// --profile beats PERMIO_PROFILE beats current_profile.
	r, _ = Resolve(f, Overrides{Profile: "other"}, env(map[string]string{EnvProfile: "work"}))
	if r.APIKey != "other-key" || r.Project != DefaultProject || r.APIURL != DefaultAPIURL {
		t.Fatalf("profile flag: %+v", r)
	}
	r, _ = Resolve(f, Overrides{}, env(map[string]string{EnvProfile: "other"}))
	if r.Profile != "other" {
		t.Fatalf("profile env: %+v", r)
	}

	// Unknown explicit profile is an error.
	if _, err := Resolve(f, Overrides{Profile: "nope"}, env(nil)); err == nil {
		t.Fatal("expected error for unknown profile")
	}
	// Missing implicit default profile is fine.
	r, err = Resolve(&File{Profiles: map[string]*Profile{}}, Overrides{}, env(nil))
	if err != nil || r.APIKeySource != SourceNone || r.Project != DefaultProject {
		t.Fatalf("empty: %+v %v", r, err)
	}
}

func TestSaveIsPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "config.yaml")
	f := &File{Profiles: map[string]*Profile{}}
	if err := f.Set("default", "api-key", "k"); err != nil {
		t.Fatal(err)
	}
	if err := f.Save(path); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, want 0600", st.Mode().Perm())
	}
	g, err := Load(path)
	if err != nil || g.Profiles["default"].APIKey != "k" {
		t.Fatalf("reload: %+v %v", g, err)
	}
	if err := f.Set("default", "colour", "x"); err == nil {
		t.Fatal("expected error for unknown key")
	}
}

func TestParseAPIURL(t *testing.T) {
	cases := map[string]Endpoint{
		"":                          {Address: DefaultAPIURL},
		"dev":                       {Address: DevAPIURL},
		"api.perms.io":              {Address: "api.perms.io:443"},
		"https://dev-api.perms.io/": {Address: "dev-api.perms.io:443"},
		"https://example.com:8443":  {Address: "example.com:8443"},
		"http://localhost:8080":     {Address: "localhost:8080", Insecure: true},
		"temp-api.perms.io:443":     {Address: "temp-api.perms.io:443"},
		"[::1]:9000":                {Address: "[::1]:9000"},
	}
	for in, want := range cases {
		got, err := ParseAPIURL(in)
		if err != nil || got != want {
			t.Errorf("ParseAPIURL(%q) = %+v, %v; want %+v", in, got, err, want)
		}
	}
	for _, bad := range []string{"ftp://x", "https://x/path"} {
		if _, err := ParseAPIURL(bad); err == nil {
			t.Errorf("ParseAPIURL(%q): expected error", bad)
		}
	}
}
