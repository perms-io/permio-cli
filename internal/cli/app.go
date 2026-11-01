// Package cli implements the permio command-line interface.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"
	"google.golang.org/grpc"

	"github.com/perms-io/permio-cli/internal/settings"
	"github.com/perms-io/permio-cli/pkg/apikey"
	"github.com/perms-io/permio-cli/pkg/permio"
)

// Exit codes.
const (
	ExitOK         = 0
	ExitDenied     = 1 // a check (or --allows test) was denied
	ExitError      = 2 // usage error or API error
	ExitAuth       = 3 // missing, malformed or rejected API key
	ExitPermission = 4 // the API key may not perform this call
)

// App holds the process environment so tests can run commands in-process.
type App struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	Getenv func(string) string
	// StdinIsTTY reports whether stdin is an interactive terminal.
	StdinIsTTY func() bool
	// DialOptions are passed to the gRPC client (tests use bufconn).
	DialOptions []grpc.DialOption

	// Global flags.
	flagAPIKey, flagAPIURL, flagProject, flagProfile string
	jsonOut, quiet                                   bool
	timeout                                          time.Duration
}

// Main runs the CLI against the real process environment and returns the exit code.
func Main() int {
	a := &App{
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
		Getenv: os.Getenv,
		StdinIsTTY: func() bool {
			return term.IsTerminal(int(os.Stdin.Fd()))
		},
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return a.Run(ctx, os.Args[1:])
}

// exitError carries an exit code. If silent, nothing more is printed.
type exitError struct {
	code   int
	err    error
	silent bool
}

func (e *exitError) Error() string {
	if e.err == nil {
		return fmt.Sprintf("exit %d", e.code)
	}
	return e.err.Error()
}

func (e *exitError) Unwrap() error { return e.err }

func usageErr(format string, args ...any) error {
	return &exitError{code: ExitError, err: fmt.Errorf(format, args...)}
}

func denied() error { return &exitError{code: ExitDenied, silent: true} }

// Run executes args and returns the exit code.
func (a *App) Run(ctx context.Context, args []string) int {
	root := a.newRoot()
	root.SetArgs(args)
	root.SetIn(a.Stdin)
	root.SetOut(a.Stdout)
	root.SetErr(a.Stderr)
	err := root.ExecuteContext(ctx)
	if err == nil {
		return ExitOK
	}
	return a.handleError(err)
}

func exitCodeFor(err error) int {
	var ee *exitError
	if errors.As(err, &ee) {
		return ee.code
	}
	switch permio.KindOf(err) {
	case permio.KindAuth:
		return ExitAuth
	case permio.KindPermission:
		return ExitPermission
	}
	return ExitError
}

func (a *App) handleError(err error) int {
	code := exitCodeFor(err)
	var ee *exitError
	if errors.As(err, &ee) && ee.silent {
		return code
	}
	var pe *permio.Error
	hasPE := errors.As(err, &pe)
	if a.jsonOut {
		body := map[string]any{"message": err.Error(), "exit_code": code, "kind": "usage"}
		if hasPE {
			body["kind"] = string(pe.Kind)
			if pe.Code != 0 {
				body["grpc_code"] = pe.Code.String()
			}
			if len(pe.Missing) > 0 {
				body["missing"] = pe.Missing
			}
		} else if code == ExitAuth {
			body["kind"] = string(permio.KindAuth)
		}
		enc := json.NewEncoder(a.Stderr)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{"error": body})
		return code
	}
	fmt.Fprintf(a.Stderr, "Error: %v\n", err)
	switch code {
	case ExitAuth:
		if hasPE && pe.Code != 0 {
			fmt.Fprintln(a.Stderr, "Hint: the API rejected this key. It may have been revoked, or belong to a different server (see --api-url). Check `permio config list` for which key is in use.")
			break
		}
		fmt.Fprintln(a.Stderr, "Hint: set an API key with --api-key, PERMIO_API_KEY or `permio config set api-key <key>`. Keys come from the dashboard at https://app.perms.io.")
	case ExitPermission:
		if hasPE && len(pe.Missing) > 0 {
			for _, m := range pe.Missing {
				fmt.Fprintf(a.Stderr, "  missing %s on %s\n", strings.Join(m.Permissions, ", "), m.Resource)
			}
		}
		fmt.Fprintln(a.Stderr, "Hint: the API key is valid but may not do this. A check-only key can check and read; creating, updating and deleting needs a full-access key. A key also only works in its own project (see --project).")
	}
	return code
}

func (a *App) newRoot() *cobra.Command {
	root := &cobra.Command{
		Use:   "permio",
		Short: "Manage and check perms.io permissions from the command line",
		Long: `permio manages a perms.io project and runs permission checks.

Model:
  permissions  named actions, e.g. document.read
  roles        named sets of permissions, addressed by ID (the CLI also accepts names)
  groups       named sets of principals; grant to the principal "group:<slug>"
  grants       roles and/or permissions given to a principal on a resource URI
  resources    hierarchical URIs like /projects/42/documents/7. A grant on a URI
               applies to everything below it, and a "_" segment in a granted
               URI matches any one segment.

Authentication:
  Every command needs an API key for one project (org + project). Give it with
  --api-key, PERMIO_API_KEY, or a profile in ~/.config/permio/config.yaml
  (permio config set api-key <key>). Precedence: flag > env > profile.
  A check-only key can check and read; a full-access key can also write.

Output:
  Human-readable by default. Add --json for stable machine-readable output on
  stdout; errors are then JSON objects on stderr. Never prompts when stdin is
  not a terminal.

Exit codes:
  0  success (check: allowed)
  1  check denied
  2  usage error or API error
  3  authentication error (missing, malformed or rejected API key)
  4  the API key is not allowed to do this (permission denied for the key)`,
		Example: `  permio config set api-key perms_...
  permio check user_123 /documents/42 document.read
  permio roles create editor --permission document.read --permission document.edit
  permio grants add --principal user_123 --resource /documents/42 --role editor
  permio export > permio.yaml && permio plan -f permio.yaml`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetFlagErrorFunc(func(c *cobra.Command, err error) error {
		return usageErr("%v (see `%s --help`)", err, c.CommandPath())
	})
	pf := root.PersistentFlags()
	pf.StringVar(&a.flagAPIKey, "api-key", "", "API key (env PERMIO_API_KEY)")
	pf.StringVar(&a.flagAPIURL, "api-url", "", `API address: host[:port], https://host or "prod" (env PERMIO_API_URL; default prod, `+settings.DefaultAPIURL+")")
	pf.StringVar(&a.flagProject, "project", "", `project name (env PERMIO_PROJECT; default "default")`)
	pf.StringVar(&a.flagProfile, "profile", "", "config profile to use (env PERMIO_PROFILE)")
	pf.BoolVar(&a.jsonOut, "json", false, "print machine-readable JSON")
	pf.BoolVarP(&a.quiet, "quiet", "q", false, "print nothing on success except requested data; check prints nothing at all")
	pf.DurationVar(&a.timeout, "timeout", 15*time.Second, "timeout per API request")

	root.AddCommand(
		a.newCheckCmd(),
		a.newPermissionsCmd(),
		a.newRolesCmd(),
		a.newGrantsCmd(),
		a.newGroupsCmd(),
		a.newAccessCmd(),
		a.newPlanCmd(),
		a.newApplyCmd(),
		a.newExportCmd(),
		a.newConfigCmd(),
		a.newVersionCmd(),
	)
	return root
}

// configPath returns the config file path.
func (a *App) configPath() (string, error) { return settings.Path(a.Getenv) }

// resolve returns the effective settings.
func (a *App) resolve() (*settings.Resolved, error) {
	path, err := a.configPath()
	if err != nil {
		return nil, err
	}
	f, err := settings.Load(path)
	if err != nil {
		return nil, usageErr("%v", err)
	}
	r, err := settings.Resolve(f, settings.Overrides{APIKey: a.flagAPIKey, APIURL: a.flagAPIURL, Project: a.flagProject, Profile: a.flagProfile}, a.Getenv)
	if err != nil {
		return nil, usageErr("%v", err)
	}
	return r, nil
}

// client builds an API client from the effective settings. project, if not
// empty, overrides the configured project.
func (a *App) client(project string) (*permio.Client, *settings.Resolved, error) {
	r, err := a.resolve()
	if err != nil {
		return nil, nil, err
	}
	if project != "" {
		r.Project = project
	}
	if _, err := apikey.Validate(r.APIKey); err != nil {
		return nil, r, &exitError{code: ExitAuth, err: err}
	}
	ep, err := settings.ParseAPIURL(r.APIURL)
	if err != nil {
		return nil, r, usageErr("%v", err)
	}
	c, err := permio.New(permio.Options{
		APIKey:      r.APIKey,
		Address:     ep.Address,
		Insecure:    ep.Insecure,
		Project:     r.Project,
		Timeout:     a.timeout,
		UserAgent:   "permio-cli/" + Version,
		DialOptions: a.DialOptions,
	})
	if err != nil {
		return nil, r, err
	}
	return c, r, nil
}

// --- output helpers ---

func (a *App) printJSON(v any) error {
	enc := json.NewEncoder(a.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// info prints a status message unless --quiet or --json.
func (a *App) info(format string, args ...any) {
	if a.quiet || a.jsonOut {
		return
	}
	fmt.Fprintf(a.Stdout, format+"\n", args...)
}

func (a *App) table() *tabwriter.Writer {
	return tabwriter.NewWriter(a.Stdout, 0, 4, 2, ' ', 0)
}

func joinOrDash(values []string) string {
	if len(values) == 0 {
		return "-"
	}
	return strings.Join(values, ", ")
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// readLines reads non-empty, trimmed lines; lines starting with # are skipped.
func readLines(r io.Reader) ([]string, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, nil
}
