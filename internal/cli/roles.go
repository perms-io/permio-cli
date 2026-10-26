package cli

import (
	"fmt"
	"sort"

	"github.com/spf13/cobra"

	"github.com/PrivateJAR/permio-cli/pkg/permio"
)

func (a *App) newRolesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "roles",
		Aliases: []string{"role"},
		Short:   "List, create, update and delete roles",
		Long: `Roles are named sets of permissions. The API addresses roles by ID; every
command here also accepts a role's exact name instead. Writing needs a
full-access key.`,
		Example: `  permio roles list
  permio roles create editor --permission document.read --permission document.edit
  permio roles update editor --add-permission document.delete
  permio roles delete editor`,
	}
	cmd.AddCommand(a.rolesList(), a.rolesGet(), a.rolesCreate(), a.rolesUpdate(), a.rolesDelete())
	return cmd
}

func (a *App) printRole(r *permio.Role) error {
	if a.jsonOut {
		return a.printJSON(r)
	}
	fmt.Fprintf(a.Stdout, "ID:           %s\nName:         %s\nDescription:  %s\nPermissions:  %s\n", r.ID, r.Name, orDash(r.Description), joinOrDash(r.Permissions))
	return nil
}

func (a *App) rolesList() *cobra.Command {
	var search string
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List every role in the project",
		Example: `  permio roles list
  permio roles list --search edit --json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, _, err := a.client("")
			if err != nil {
				return err
			}
			defer c.Close()
			roles, err := c.ListRoles(cmd.Context(), search)
			if err != nil {
				return err
			}
			if a.jsonOut {
				return a.printJSON(map[string]any{"roles": roles})
			}
			if a.quiet {
				for _, r := range roles {
					fmt.Fprintln(a.Stdout, r.ID)
				}
				return nil
			}
			if len(roles) == 0 {
				fmt.Fprintln(a.Stdout, "No roles.")
				return nil
			}
			w := a.table()
			fmt.Fprintln(w, "NAME\tID\tPERMISSIONS\tDESCRIPTION")
			for _, r := range roles {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", r.Name, r.ID, joinOrDash(r.Permissions), orDash(r.Description))
			}
			return w.Flush()
		},
	}
	cmd.Flags().StringVar(&search, "search", "", "only roles whose name contains this text")
	return cmd
}

func (a *App) rolesGet() *cobra.Command {
	return &cobra.Command{
		Use:     "get <id-or-name>",
		Short:   "Show one role",
		Example: `  permio roles get editor --json`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, _, err := a.client("")
			if err != nil {
				return err
			}
			defer c.Close()
			r, err := c.ResolveRole(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			return a.printRole(r)
		},
	}
}

func (a *App) rolesCreate() *cobra.Command {
	var description string
	var perms []string
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a role",
		Long:  `Create a role. Its permissions must already exist. Role names are unique: creating a role whose name is taken returns that role, and a --description or --permission list that differs replaces the stored one.`,
		Example: `  permio roles create editor --permission document.read,document.edit --description "Can edit documents"
  permio roles create viewer -p document.read --json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, _, err := a.client("")
			if err != nil {
				return err
			}
			defer c.Close()
			r, err := c.CreateRole(cmd.Context(), args[0], description, perms)
			if err != nil {
				return err
			}
			if a.jsonOut {
				return a.printJSON(r)
			}
			a.info("Created role %s (ID %s)", r.Name, r.ID)
			return nil
		},
	}
	cmd.Flags().StringVar(&description, "description", "", "description")
	cmd.Flags().StringSliceVarP(&perms, "permission", "p", nil, "permission in the role (repeatable or comma-separated)")
	return cmd
}

func (a *App) rolesUpdate() *cobra.Command {
	var name, description string
	var set, add, remove []string
	cmd := &cobra.Command{
		Use:   "update <id-or-name>",
		Short: "Rename a role or change its description or permissions",
		Long: `Change a role. Flags you leave out keep their current value.
--permission replaces the whole permission list; --add-permission and
--remove-permission change it incrementally (applied after --permission).`,
		Example: `  permio roles update editor --add-permission document.delete
  permio roles update editor --remove-permission document.delete --description "No deletes"
  permio roles update editor --permission document.read --permission document.edit
  permio roles update role_abc123 --name writer`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			f := cmd.Flags()
			if !f.Changed("name") && !f.Changed("description") && !f.Changed("permission") && len(add) == 0 && len(remove) == 0 {
				return usageErr("nothing to change: give --name, --description, --permission, --add-permission or --remove-permission")
			}
			c, _, err := a.client("")
			if err != nil {
				return err
			}
			defer c.Close()
			r, err := c.ResolveRole(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			perms := r.Permissions
			if f.Changed("permission") {
				perms = set
			}
			final := map[string]bool{}
			for _, p := range perms {
				final[p] = true
			}
			for _, p := range add {
				final[p] = true
			}
			for _, p := range remove {
				delete(final, p)
			}
			perms = perms[:0:0]
			for p := range final {
				perms = append(perms, p)
			}
			sort.Strings(perms)
			if !f.Changed("name") {
				name = r.Name
			}
			if !f.Changed("description") {
				description = r.Description
			}
			updated, err := c.UpdateRole(cmd.Context(), r.ID, name, description, perms)
			if err != nil {
				return err
			}
			if a.jsonOut {
				return a.printJSON(updated)
			}
			a.info("Updated role %s (ID %s); permissions: %s", updated.Name, updated.ID, joinOrDash(updated.Permissions))
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "new name")
	cmd.Flags().StringVar(&description, "description", "", "new description")
	cmd.Flags().StringSliceVarP(&set, "permission", "p", nil, "replace the permission list (repeatable or comma-separated)")
	cmd.Flags().StringSliceVar(&add, "add-permission", nil, "add a permission (repeatable or comma-separated)")
	cmd.Flags().StringSliceVar(&remove, "remove-permission", nil, "remove a permission (repeatable or comma-separated)")
	return cmd
}

func (a *App) rolesDelete() *cobra.Command {
	return &cobra.Command{
		Use:     "delete <id-or-name...>",
		Short:   "Delete one or more roles",
		Example: `  permio roles delete editor`,
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, _, err := a.client("")
			if err != nil {
				return err
			}
			defer c.Close()
			roles, err := c.ListRoles(cmd.Context(), "")
			if err != nil {
				return err
			}
			deleted := []permio.RoleRef{}
			for _, ref := range args {
				r, err := permio.FindRole(roles, ref)
				if err != nil {
					return err
				}
				if err := c.DeleteRole(cmd.Context(), r.ID); err != nil {
					return fmt.Errorf("deleting role %s: %w", r.Name, err)
				}
				deleted = append(deleted, permio.RoleRef{ID: r.ID, Name: r.Name})
				a.info("Deleted role %s (ID %s)", r.Name, r.ID)
			}
			if a.jsonOut {
				return a.printJSON(map[string]any{"deleted": deleted})
			}
			return nil
		},
	}
}
