package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/perms-io/permio-cli/internal/settings"
	"github.com/perms-io/permio-cli/pkg/configsync"
	"github.com/perms-io/permio-cli/pkg/permio"
)

const fileFormatHelp = `File format (permio.yaml):

  project: default                     # optional; defaults to the configured project
  permissions:                         # a name, or {name, description}
    - document.read
    - { name: document.edit, description: Edit documents }
  roles:                               # keyed by role NAME
    editor:
      description: Can edit documents  # optional
      permissions: [document.read, document.edit]   # the role's full permission set
  groups:                              # keyed by group slug
    design:
      description: Design team         # optional
      members: [user_123, user_456]    # optional; when given, the full member list
  grants:                              # each entry is the FULL set for that pair
    - { principal: group:design, resource: /projects/123, roles: [editor], permissions: [] }

Semantics: objects in the file are created or updated. A role's permissions, a
group's members (when listed) and a grant's roles and permissions are each the
full set, so extras are removed. An omitted description is left unchanged.
Without --prune, objects in the project that are not in the file are kept; with
--prune they are deleted (permissions, roles, groups, and grants for
principal/resource pairs the file does not list).

JSON Schema for editor autocompletion: schema/permio.schema.json in the
permio-cli repository (exported files reference it).`

func (a *App) readConfigFile(path string) (*configsync.File, error) {
	var data []byte
	var err error
	if path == "-" {
		data, err = io.ReadAll(a.Stdin)
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, usageErr("reading %s: %v", path, err)
	}
	f, err := configsync.Parse(data)
	if err != nil {
		return nil, usageErr("%s: %v", path, err)
	}
	return f, nil
}

// syncTarget resolves the project for a config file and returns a client for it.
func (a *App) syncTarget(f *configsync.File) (*permio.Client, error) {
	r, err := a.resolve()
	if err != nil {
		return nil, err
	}
	project := r.Project
	if f.Project != "" {
		if (r.ProjectSource == settings.SourceFlag || r.ProjectSource == settings.SourceEnv) && r.Project != f.Project {
			return nil, usageErr("the file is for project %q but --project/PERMIO_PROJECT is %q; remove one of them", f.Project, r.Project)
		}
		project = f.Project
	}
	f.Project = project
	c, _, err := a.client(project)
	return c, err
}

func (a *App) computePlan(ctx context.Context, path string, prune bool) (*permio.Client, *configsync.Plan, *configsync.State, error) {
	f, err := a.readConfigFile(path)
	if err != nil {
		return nil, nil, nil, err
	}
	c, err := a.syncTarget(f)
	if err != nil {
		return nil, nil, nil, err
	}
	state, err := configsync.Fetch(ctx, c)
	if err != nil {
		c.Close()
		return nil, nil, nil, err
	}
	plan, err := configsync.ComputePlan(f, state, configsync.Options{Prune: prune})
	if err != nil {
		c.Close()
		var ve *configsync.ValidationError
		if errors.As(err, &ve) {
			return nil, nil, nil, usageErr("%s: %v", path, err)
		}
		return nil, nil, nil, err
	}
	return c, plan, state, nil
}

func (a *App) newPlanCmd() *cobra.Command {
	var path string
	var prune bool
	cmd := &cobra.Command{
		Use:   "plan [-f permio.yaml] [--prune]",
		Short: "Show what apply would change, without changing anything",
		Long: `Compare a permio.yaml file with the project and print the changes apply would
make: + create, ~ update, - delete. Nothing is changed. Needs only a check-only
(read) key.

` + fileFormatHelp,
		Example: `  permio plan -f permio.yaml
  permio plan -f permio.yaml --prune --json
  cat permio.yaml | permio plan -f -`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, plan, _, err := a.computePlan(cmd.Context(), path, prune)
			if err != nil {
				return err
			}
			defer c.Close()
			if a.jsonOut {
				return a.printJSON(plan)
			}
			if a.quiet {
				return nil
			}
			plan.Render(a.Stdout)
			return nil
		},
	}
	cmd.Flags().StringVarP(&path, "file", "f", "permio.yaml", `config file ("-" for stdin)`)
	cmd.Flags().BoolVar(&prune, "prune", false, "also plan deletion of objects not in the file")
	return cmd
}

type applyOutput struct {
	Project string              `json:"project"`
	Plan    *configsync.Plan    `json:"plan"`
	Applied []configsync.Change `json:"applied"`
	Summary configsync.Summary  `json:"summary"`
}

func (a *App) newApplyCmd() *cobra.Command {
	var path string
	var prune, yes bool
	cmd := &cobra.Command{
		Use:   "apply [-f permio.yaml] [--prune] [--yes]",
		Short: "Make the project match a permio.yaml file",
		Long: `Compute the plan (see 'permio plan'), show it, ask for confirmation and apply
it. Changes run in dependency order: permissions, roles, groups, members,
grants; with --prune, deletions follow in reverse order (grants, groups, roles,
permissions). Applying the same file twice makes no further changes. Needs a
full-access key.

Confirmation: you are asked to type "yes" unless --yes is given. When stdin is
not a terminal, or with --json, there is no prompt and --yes is required. If a
change fails, apply stops; the changes before it stay applied, and running apply
again continues from there.

` + fileFormatHelp,
		Example: `  permio apply -f permio.yaml
  permio apply -f permio.yaml --prune --yes
  permio apply -f permio.yaml --yes --json   # CI / agents`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if !yes && (path == "-" || !a.StdinIsTTY() || a.jsonOut) {
				return usageErr("refusing to apply without confirmation: pass --yes (stdin is not an interactive terminal, or --json was given)")
			}
			c, plan, state, err := a.computePlan(ctx, path, prune)
			if err != nil {
				return err
			}
			defer c.Close()
			out := applyOutput{Project: plan.Project, Plan: plan, Applied: []configsync.Change{}}
			if plan.Empty() {
				if a.jsonOut {
					return a.printJSON(out)
				}
				a.info("No changes. Project %q matches the file.", plan.Project)
				return nil
			}
			if !a.jsonOut && !a.quiet {
				plan.Render(a.Stdout)
				fmt.Fprintln(a.Stdout)
			}
			if !yes {
				fmt.Fprintf(a.Stderr, "Apply these changes to project %q? Type \"yes\" to continue: ", plan.Project)
				answer, _ := bufio.NewReader(a.Stdin).ReadString('\n')
				if strings.TrimSpace(strings.ToLower(answer)) != "yes" {
					fmt.Fprintln(a.Stderr, "Cancelled; nothing was changed.")
					return &exitError{code: ExitError, silent: true}
				}
			}
			res, err := configsync.Apply(ctx, c, plan, state, func(ch configsync.Change) {
				a.info("  done  %s", ch.Describe())
			})
			out.Applied, out.Summary = res.Applied, res.Summary
			if a.jsonOut {
				if perr := a.printJSON(out); perr != nil && err == nil {
					return perr
				}
			}
			if err != nil {
				return err
			}
			a.info("\nApplied: %d created, %d updated, %d deleted.", res.Summary.Create, res.Summary.Update, res.Summary.Delete)
			return nil
		},
	}
	cmd.Flags().StringVarP(&path, "file", "f", "permio.yaml", `config file ("-" for stdin; requires --yes)`)
	cmd.Flags().BoolVar(&prune, "prune", false, "also delete objects in the project that are not in the file")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "apply without asking for confirmation")
	return cmd
}

func (a *App) newExportCmd() *cobra.Command {
	var output string
	cmd := &cobra.Command{
		Use:   "export [-o permio.yaml]",
		Short: "Print the project's current state as a permio.yaml file",
		Long: `Export the project's permissions, roles, groups (with members) and grants as
a permio.yaml file. Planning the exported file against the same project shows
no changes, so it is a starting point for managing the project as code. Needs
only a check-only (read) key.

` + fileFormatHelp,
		Example: `  permio export > permio.yaml
  permio export -o permio.yaml --project staging
  permio export --json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, r, err := a.client("")
			if err != nil {
				return err
			}
			defer c.Close()
			state, err := configsync.Fetch(cmd.Context(), c)
			if err != nil {
				return err
			}
			f, err := state.Export(r.Project)
			if err != nil {
				return err
			}
			if a.jsonOut {
				return a.printJSON(f)
			}
			data, err := f.Marshal()
			if err != nil {
				return err
			}
			if output == "" || output == "-" {
				_, err = a.Stdout.Write(data)
				return err
			}
			if err := os.WriteFile(output, data, 0o644); err != nil {
				return err
			}
			a.info("Wrote %s", output)
			return nil
		},
	}
	cmd.Flags().StringVarP(&output, "output", "o", "", "write to this file instead of stdout")
	return cmd
}
