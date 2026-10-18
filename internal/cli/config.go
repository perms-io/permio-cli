package cli

import (
	"fmt"
	"runtime/debug"
	"strings"

	"github.com/spf13/cobra"

	"github.com/PrivateJAR/permio-cli/internal/settings"
	"github.com/PrivateJAR/permio-cli/pkg/apikey"
)

// Set at build time with -ldflags "-X github.com/PrivateJAR/permio-cli/internal/cli.Version=...".
var (
	Version = "dev"
	Commit  = ""
	Date    = ""
)

func (a *App) newConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Manage profiles in the config file",
		Long: `Manage named profiles in the config file (by default
~/.config/permio/config.yaml, or $PERMIO_CONFIG). Each profile holds an API key,
an API URL and a project. The file is written with 0600 permissions.

Select a profile with --profile, PERMIO_PROFILE, or 'permio config use'.
Flags and environment variables override profile values.`,
		Example: `  permio config set api-key perms_...
  permio config set --profile dev api-url dev
  permio config set --profile dev project staging
  permio config use dev
  permio config list`,
	}
	cmd.AddCommand(a.configSet(), a.configUnset(), a.configUse(), a.configList(), a.configPathCmd())
	return cmd
}

func (a *App) configTarget() string {
	if a.flagProfile != "" {
		return a.flagProfile
	}
	return ""
}

func (a *App) configSet() *cobra.Command {
	return &cobra.Command{
		Use:   "set <key> <value>",
		Short: "Set api-key, api-url or project in a profile",
		Long: `Set a value in a profile, creating the profile if needed. Keys: api-key,
api-url, project. The profile is --profile, else the current profile, else
"default". Use "-" as the value to read it from stdin (keeps keys out of shell
history). API keys are checked for the right format before saving.`,
		Example: `  permio config set api-key perms_...
  printf '%s' "$KEY" | permio config set api-key -
  permio config set --profile dev api-url dev
  permio config set project my-app`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			key, value := args[0], args[1]
			if value == "-" {
				lines, err := readLines(a.Stdin)
				if err != nil {
					return err
				}
				if len(lines) != 1 {
					return usageErr("expected exactly one line on stdin")
				}
				value = lines[0]
			}
			switch key {
			case "api-key", "api_key":
				if _, err := apikey.Validate(value); err != nil {
					return &exitError{code: ExitAuth, err: err}
				}
			case "api-url", "api_url":
				if _, err := settings.ParseAPIURL(value); err != nil {
					return usageErr("%v", err)
				}
			}
			path, err := a.configPath()
			if err != nil {
				return err
			}
			f, err := settings.Load(path)
			if err != nil {
				return usageErr("%v", err)
			}
			profile := a.configTarget()
			if profile == "" {
				profile = f.CurrentProfile
			}
			if profile == "" {
				profile = settings.DefaultProfile
			}
			if err := f.Set(profile, key, value); err != nil {
				return usageErr("%v", err)
			}
			if err := f.Save(path); err != nil {
				return err
			}
			if a.jsonOut {
				return a.printJSON(map[string]any{"profile": profile, "key": key, "path": path})
			}
			a.info("Set %s in profile %q (%s)", key, profile, path)
			return nil
		},
	}
}

func (a *App) configUnset() *cobra.Command {
	return &cobra.Command{
		Use:     "unset <key>",
		Short:   "Remove api-key, api-url or project from a profile",
		Example: `  permio config unset --profile dev api-key`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := a.configPath()
			if err != nil {
				return err
			}
			f, err := settings.Load(path)
			if err != nil {
				return usageErr("%v", err)
			}
			profile := a.configTarget()
			if profile == "" {
				profile = f.CurrentProfile
			}
			if profile == "" {
				profile = settings.DefaultProfile
			}
			if _, ok := f.Profiles[profile]; !ok {
				return usageErr("profile %q not found", profile)
			}
			if err := f.Set(profile, args[0], ""); err != nil {
				return usageErr("%v", err)
			}
			if err := f.Save(path); err != nil {
				return err
			}
			a.info("Removed %s from profile %q", args[0], profile)
			return nil
		},
	}
}

func (a *App) configUse() *cobra.Command {
	return &cobra.Command{
		Use:     "use <profile>",
		Short:   "Make a profile the current one",
		Example: `  permio config use dev`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := a.configPath()
			if err != nil {
				return err
			}
			f, err := settings.Load(path)
			if err != nil {
				return usageErr("%v", err)
			}
			if _, ok := f.Profiles[args[0]]; !ok {
				return usageErr("profile %q not found (create it with `permio config set --profile %s api-key ...`)", args[0], args[0])
			}
			f.CurrentProfile = args[0]
			if err := f.Save(path); err != nil {
				return err
			}
			a.info("Current profile is now %q", args[0])
			return nil
		},
	}
}

type profileView struct {
	Name    string `json:"name"`
	Current bool   `json:"current"`
	APIKey  string `json:"api_key"`
	APIURL  string `json:"api_url"`
	Project string `json:"project"`
}

func (a *App) configList() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List profiles (keys redacted) and the effective settings",
		Example: `  permio config list
  permio config list --json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := a.configPath()
			if err != nil {
				return err
			}
			f, err := settings.Load(path)
			if err != nil {
				return usageErr("%v", err)
			}
			current := f.CurrentProfile
			if current == "" {
				current = settings.DefaultProfile
			}
			profiles := []profileView{}
			for _, name := range f.ProfileNames() {
				p := f.Profiles[name]
				profiles = append(profiles, profileView{Name: name, Current: name == current, APIKey: apikey.Redact(p.APIKey), APIURL: p.APIURL, Project: p.Project})
			}
			var effective any
			var resolveErr string
			if r, err := a.resolve(); err == nil {
				effective = map[string]any{
					"profile": r.Profile, "api_key": apikey.Redact(r.APIKey), "api_key_source": r.APIKeySource,
					"api_url": r.APIURL, "api_url_source": r.APIURLSource, "project": r.Project, "project_source": r.ProjectSource,
				}
			} else {
				resolveErr = err.Error()
			}
			if a.jsonOut {
				out := map[string]any{"path": path, "current_profile": current, "profiles": profiles, "effective": effective}
				if resolveErr != "" {
					out["effective_error"] = resolveErr
				}
				return a.printJSON(out)
			}
			fmt.Fprintf(a.Stdout, "Config file: %s\n\n", path)
			if len(profiles) == 0 {
				fmt.Fprintln(a.Stdout, "No profiles. Create one with `permio config set api-key <key>`.")
			} else {
				w := a.table()
				fmt.Fprintln(w, "\tPROFILE\tAPI KEY\tAPI URL\tPROJECT")
				for _, p := range profiles {
					mark := ""
					if p.Current {
						mark = "*"
					}
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", mark, p.Name, orDash(p.APIKey), orDash(p.APIURL), orDash(p.Project))
				}
				w.Flush()
			}
			if resolveErr != "" {
				fmt.Fprintf(a.Stdout, "\nEffective settings: %s\n", resolveErr)
				return nil
			}
			r, _ := a.resolve()
			fmt.Fprintf(a.Stdout, "\nEffective settings (profile %q):\n  api key  %s (%s)\n  api url  %s (%s)\n  project  %s (%s)\n",
				r.Profile, orDash(apikey.Redact(r.APIKey)), r.APIKeySource, r.APIURL, r.APIURLSource, r.Project, r.ProjectSource)
			return nil
		},
	}
}

func (a *App) configPathCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "path",
		Short:   "Print the config file path",
		Example: `  permio config path`,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := a.configPath()
			if err != nil {
				return err
			}
			if a.jsonOut {
				return a.printJSON(map[string]string{"path": path})
			}
			fmt.Fprintln(a.Stdout, path)
			return nil
		},
	}
}

func (a *App) newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "version",
		Short:   "Print the version",
		Example: `  permio version --json`,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			v, commit, date := Version, Commit, Date
			if v == "dev" {
				if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
					v = strings.TrimPrefix(info.Main.Version, "v")
				}
			}
			if a.jsonOut {
				return a.printJSON(map[string]string{"version": v, "commit": commit, "date": date})
			}
			line := "permio " + v
			if commit != "" {
				line += " (" + commit
				if date != "" {
					line += ", " + date
				}
				line += ")"
			}
			fmt.Fprintln(a.Stdout, line)
			return nil
		},
	}
}
