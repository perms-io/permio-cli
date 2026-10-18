package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/PrivateJAR/permio-cli/pkg/permio"
)

type checkOutput struct {
	Allowed     bool                       `json:"allowed"`
	Principal   string                     `json:"principal"`
	Resource    string                     `json:"resource"`
	Permissions []string                   `json:"permissions"`
	Missing     []permio.MissingPermission `json:"missing"`
}

func (a *App) newCheckCmd() *cobra.Command {
	var explain bool
	cmd := &cobra.Command{
		Use:   "check <principal> <resource> <permission...>",
		Short: "Check whether a principal holds permissions on a resource",
		Long: `Check whether a principal holds every given permission on a resource.

The answer counts grants on the resource and on its ancestors, stored "_"
wildcard grants, roles, and the groups the principal is a member of.

Exit code 0 means allowed, 1 means denied, 2 or higher means the check could not
be made (see permio --help). A denial is a normal result, not an error.`,
		Example: `  # Exit code only, for scripts
  permio check user_123 /documents/42 document.read -q && echo allowed

  # Several permissions at once (all must be held), with what is missing
  permio check user_123 /documents/42 document.read document.edit --explain

  # Machine-readable
  permio check user_123 /documents/42 document.read --json`,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) < 3 {
				return usageErr("check needs <principal> <resource> <permission...>, got %d argument(s) (see `permio check --help`)", len(args))
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			c, _, err := a.client("")
			if err != nil {
				return err
			}
			defer c.Close()
			principal, resource, perms := args[0], args[1], args[2:]
			res, err := c.Check(cmd.Context(), principal, []string{resource}, perms)
			if err != nil {
				return err
			}
			switch {
			case a.jsonOut:
				if err := a.printJSON(checkOutput{Allowed: res.Allowed, Principal: principal, Resource: resource, Permissions: perms, Missing: res.Missing}); err != nil {
					return err
				}
			case a.quiet:
			default:
				if res.Allowed {
					fmt.Fprintf(a.Stdout, "allowed: %s has %s on %s\n", principal, strings.Join(perms, ", "), resource)
				} else {
					fmt.Fprintf(a.Stdout, "denied: %s does not have %s on %s\n", principal, strings.Join(missingOn(res.Missing, perms), ", "), resource)
					if explain {
						for _, m := range res.Missing {
							fmt.Fprintf(a.Stdout, "  missing on %s: %s\n", m.Resource, strings.Join(m.Permissions, ", "))
						}
					}
				}
			}
			if !res.Allowed {
				return denied()
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&explain, "explain", false, "on denial, list the missing permissions per resource")
	cmd.AddCommand(a.newCheckBatchCmd())
	return cmd
}

func missingOn(missing []permio.MissingPermission, fallback []string) []string {
	var out []string
	for _, m := range missing {
		out = append(out, m.Permissions...)
	}
	if len(out) == 0 {
		return fallback
	}
	return out
}

type batchOutput struct {
	AllAllowed  bool                 `json:"all_allowed"`
	Principal   string               `json:"principal"`
	Permissions []string             `json:"permissions"`
	Results     []permio.BatchResult `json:"results"`
	Allowed     int                  `json:"allowed_count"`
	Denied      int                  `json:"denied_count"`
}

func (a *App) newCheckBatchCmd() *cobra.Command {
	var perms []string
	cmd := &cobra.Command{
		Use:   "batch <principal> --permission <name> [resource...]",
		Short: "Check many resources at once, one answer per resource",
		Long: `Check each resource separately and print one answer per resource.

Resources come from the arguments, or from stdin (one per line; blank lines and
lines starting with # are ignored) when there are none or the only one is "-".
More than 100 resources are split into several calls.

Exit code 0 means every resource is allowed, 1 means at least one is denied.`,
		Example: `  permio check batch user_123 --permission document.read /documents/1 /documents/2
  cat uris.txt | permio check batch user_123 -p document.read --json
  permio check batch user_123 -p document.read -p document.edit - < uris.txt`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(perms) == 0 {
				return usageErr("give at least one --permission")
			}
			principal, resources := args[0], args[1:]
			if len(resources) == 0 || (len(resources) == 1 && resources[0] == "-") {
				lines, err := readLines(a.Stdin)
				if err != nil {
					return err
				}
				resources = lines
			}
			if len(resources) == 0 {
				return usageErr("no resources given (pass them as arguments or on stdin)")
			}
			c, _, err := a.client("")
			if err != nil {
				return err
			}
			defer c.Close()
			results, err := c.BatchCheck(cmd.Context(), principal, resources, perms)
			if err != nil {
				return err
			}
			out := batchOutput{AllAllowed: true, Principal: principal, Permissions: perms, Results: results}
			for _, r := range results {
				if r.Allowed {
					out.Allowed++
				} else {
					out.Denied++
					out.AllAllowed = false
				}
			}
			switch {
			case a.jsonOut:
				if err := a.printJSON(out); err != nil {
					return err
				}
			case a.quiet:
			default:
				w := a.table()
				fmt.Fprintln(w, "RESOURCE\tRESULT\tMISSING")
				for _, r := range results {
					result := "allowed"
					if !r.Allowed {
						result = "denied"
					}
					fmt.Fprintf(w, "%s\t%s\t%s\n", r.Resource, result, joinOrDash(r.Missing))
				}
				w.Flush()
				fmt.Fprintf(a.Stdout, "\n%d allowed, %d denied\n", out.Allowed, out.Denied)
			}
			if !out.AllAllowed {
				return denied()
			}
			return nil
		},
	}
	cmd.Flags().StringSliceVarP(&perms, "permission", "p", nil, "permission to check (repeatable or comma-separated); all must be held")
	return cmd
}
