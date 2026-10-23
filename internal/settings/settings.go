// Package settings loads and saves the CLI's config file and resolves the
// effective connection settings from flags, environment and profiles.
//
// Precedence, highest first: command-line flag, environment variable, the
// selected profile in the config file, built-in default.
package settings

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	// DefaultAPIURL is the production gateway.
	DefaultAPIURL = "api.perms.io:443"
	// DevAPIURL is the development gateway.
	DevAPIURL = "dev-api.perms.io:443"
	// DefaultProject is created with every organisation.
	DefaultProject = "default"
	// DefaultProfile is used when no profile is selected.
	DefaultProfile = "default"

	EnvAPIKey  = "PERMIO_API_KEY"
	EnvAPIURL  = "PERMIO_API_URL"
	EnvProject = "PERMIO_PROJECT"
	EnvProfile = "PERMIO_PROFILE"
	EnvConfig  = "PERMIO_CONFIG"
)

// Profile is one named set of connection settings.
type Profile struct {
	APIKey  string `yaml:"api_key,omitempty" json:"api_key,omitempty"`
	APIURL  string `yaml:"api_url,omitempty" json:"api_url,omitempty"`
	Project string `yaml:"project,omitempty" json:"project,omitempty"`
}

// File is the config file, by default ~/.config/permio/config.yaml.
type File struct {
	CurrentProfile string              `yaml:"current_profile,omitempty"`
	Profiles       map[string]*Profile `yaml:"profiles,omitempty"`
}

// Keys are the settable profile fields, as used by `permio config set`.
var Keys = []string{"api-key", "api-url", "project"}

// Path returns the config file path: $PERMIO_CONFIG, else
// $XDG_CONFIG_HOME/permio/config.yaml, else ~/.config/permio/config.yaml.
func Path(getenv func(string) string) (string, error) {
	if p := getenv(EnvConfig); p != "" {
		return p, nil
	}
	if x := getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "permio", "config.yaml"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot find the home directory: %w", err)
	}
	return filepath.Join(home, ".config", "permio", "config.yaml"), nil
}

// Load reads the config file. A missing file is an empty config.
func Load(path string) (*File, error) {
	f := &File{Profiles: map[string]*Profile{}}
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return f, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	if err := yaml.Unmarshal(data, f); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if f.Profiles == nil {
		f.Profiles = map[string]*Profile{}
	}
	for name, p := range f.Profiles {
		if p == nil {
			f.Profiles[name] = &Profile{}
		}
	}
	return f, nil
}

// Save writes the config file with 0600 permissions (it holds API keys),
// creating its directory with 0700.
func (f *File) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("creating config directory: %w", err)
	}
	data, err := yaml.Marshal(f)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".config-*.yaml")
	if err != nil {
		return fmt.Errorf("writing config: %w", err)
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("writing config: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("writing config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("writing config: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("writing config: %w", err)
	}
	return os.Chmod(path, 0o600)
}

// ProfileNames returns the profile names, sorted.
func (f *File) ProfileNames() []string {
	names := make([]string, 0, len(f.Profiles))
	for n := range f.Profiles {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Set sets one key of a profile, creating the profile if needed.
func (f *File) Set(profile, key, value string) error {
	p := f.Profiles[profile]
	if p == nil {
		p = &Profile{}
		f.Profiles[profile] = p
	}
	switch key {
	case "api-key", "api_key":
		p.APIKey = value
	case "api-url", "api_url":
		p.APIURL = value
	case "project":
		p.Project = value
	default:
		return fmt.Errorf("unknown key %q (valid keys: %s)", key, strings.Join(Keys, ", "))
	}
	return nil
}

// Source says where a resolved value came from.
type Source string

const (
	SourceFlag    Source = "flag"
	SourceEnv     Source = "env"
	SourceProfile Source = "profile"
	SourceDefault Source = "default"
	SourceNone    Source = "none"
)

// Overrides are the values given on the command line ("" means not given).
type Overrides struct {
	APIKey  string
	APIURL  string
	Project string
	Profile string
}

// Resolved is the effective configuration for one command.
type Resolved struct {
	Profile       string `json:"profile"`
	ProfileExists bool   `json:"profile_exists"`
	APIKey        string `json:"-"`
	APIURL        string `json:"api_url"`
	Project       string `json:"project"`
	APIKeySource  Source `json:"api_key_source"`
	APIURLSource  Source `json:"api_url_source"`
	ProjectSource Source `json:"project_source"`
}

// Resolve applies flag > env > profile > default for each setting.
func Resolve(f *File, o Overrides, getenv func(string) string) (*Resolved, error) {
	r := &Resolved{}
	switch {
	case o.Profile != "":
		r.Profile = o.Profile
	case getenv(EnvProfile) != "":
		r.Profile = getenv(EnvProfile)
	case f.CurrentProfile != "":
		r.Profile = f.CurrentProfile
	default:
		r.Profile = DefaultProfile
	}
	p, ok := f.Profiles[r.Profile]
	r.ProfileExists = ok
	if !ok {
		// Naming a profile that does not exist is a mistake; the implicit default may be absent.
		if o.Profile != "" || getenv(EnvProfile) != "" || f.CurrentProfile != "" {
			return nil, fmt.Errorf("profile %q not found in the config file (see `permio config list`)", r.Profile)
		}
		p = &Profile{}
	}
	r.APIKey, r.APIKeySource = pick(o.APIKey, getenv(EnvAPIKey), p.APIKey, "")
	r.APIURL, r.APIURLSource = pick(o.APIURL, getenv(EnvAPIURL), p.APIURL, DefaultAPIURL)
	r.Project, r.ProjectSource = pick(o.Project, getenv(EnvProject), p.Project, DefaultProject)
	return r, nil
}

func pick(flag, env, profile, def string) (string, Source) {
	switch {
	case flag != "":
		return flag, SourceFlag
	case env != "":
		return env, SourceEnv
	case profile != "":
		return profile, SourceProfile
	case def != "":
		return def, SourceDefault
	default:
		return "", SourceNone
	}
}

// Endpoint is a parsed API URL.
type Endpoint struct {
	// Address is host:port for gRPC.
	Address string
	// Insecure is true for http:// URLs (local development only).
	Insecure bool
}

// ParseAPIURL accepts "host", "host:port", "https://host[:port]",
// "http://host:port" (plaintext, for local servers) and the aliases "prod" and
// "dev". The port defaults to 443 (80 for http://).
func ParseAPIURL(raw string) (Endpoint, error) {
	s := strings.TrimSpace(raw)
	switch strings.ToLower(s) {
	case "", "prod", "production":
		return Endpoint{Address: DefaultAPIURL}, nil
	case "dev", "development":
		return Endpoint{Address: DevAPIURL}, nil
	}
	insecure := false
	port := "443"
	switch {
	case strings.HasPrefix(s, "https://"):
		s = strings.TrimPrefix(s, "https://")
	case strings.HasPrefix(s, "http://"):
		s = strings.TrimPrefix(s, "http://")
		insecure = true
		port = "80"
	case strings.Contains(s, "://"):
		return Endpoint{}, fmt.Errorf("invalid API URL %q: only https:// and http:// are supported", raw)
	}
	s = strings.TrimRight(s, "/")
	if strings.Contains(s, "/") {
		return Endpoint{}, fmt.Errorf("invalid API URL %q: it must not have a path", raw)
	}
	if s == "" {
		return Endpoint{}, fmt.Errorf("invalid API URL %q", raw)
	}
	if !hasPort(s) {
		s = s + ":" + port
	}
	return Endpoint{Address: s, Insecure: insecure}, nil
}

func hasPort(hostport string) bool {
	if strings.HasPrefix(hostport, "[") { // IPv6 literal
		return strings.Contains(hostport, "]:")
	}
	return strings.Contains(hostport, ":")
}
