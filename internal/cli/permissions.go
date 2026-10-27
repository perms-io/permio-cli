package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func (a *App) newPermissionsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "permissions",
		Aliases: []string{"permission", "perms"},
		Short:   "List, create, update and delete permissions",
		Long: `Permissions are named actions such as document.read. Names are 1-128
characters of a-z, A-Z, 0-9, '.', '_' and '-'. Writing needs a full-access key.`,
		Example: `  permio permissions list
  permio permissions create document.read --description "Read documents"
  permio permissions delete document.read`,
	}
	cmd.AddCommand(a.permissionsList(), a.permissionsGet(), a.permissionsCreate(), a.permissionsUpdate(), a.permissionsDelete())
	return cmd
}

func (a *App) permissionsList() *cobra.Command {
	var search string
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List every permission in the project",
		Example: `  permio permissions list
  permio permissions list --search document --json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, _, err := a.client("")
			if err != nil {
				return err
			}
			defer c.Close()
			perms, err := c.ListPermissions(cmd.Context(), search)
			if err != nil {
				return err
			}
			if a.jsonOut {
				return a.printJSON(map[string]any{"permissions": perms})
			}
			if a.quiet {
				for _, p := range perms {
					fmt.Fprintln(a.Stdout, p.Name)
				}
				return nil
			}
			if len(perms) == 0 {
				fmt.Fprintln(a.Stdout, "No permissions.")
				return nil
			}
			w := a.table()
			fmt.Fprintln(w, "NAME\tDESCRIPTION")
			for _, p := range perms {
				fmt.Fprintf(w, "%s\t%s\n", p.Name, orDash(p.Description))
			}
			return w.Flush()
		},
	}
	cmd.Flags().StringVar(&search, "search", "", "only permissions whose name contains this text")
	return cmd
}

func (a *App) permissionsGet() *cobra.Command {
	return &cobra.Command{
		Use:     "get <name>",
		Short:   "Show one permission",
		Example: `  permio permissions get document.read --json`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, _, err := a.client("")
			if err != nil {
				return err
			}
			defer c.Close()
			p, err := c.GetPermission(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if a.jsonOut {
				return a.printJSON(p)
			}
			fmt.Fprintf(a.Stdout, "Name:         %s\nDescription:  %s\n", p.Name, orDash(p.Description))
			return nil
		},
	}
}

func (a *App) permissionsCreate() *cobra.Command {
	var description string
	cmd := &cobra.Command{
		Use:   "create <name...>",
		Short: "Create one or more permissions",
		Long:  `Create permissions. Creating a permission that already exists succeeds: a --description that differs replaces the stored one, and leaving --description out keeps it.`,
		Example: `  permio permissions create document.read --description "Read documents"
  permio permissions create document.read document.edit document.delete`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, _, err := a.client("")
			if err != nil {
				return err
			}
			defer c.Close()
			var created []any
			for _, name := range args {
				p, err := c.CreatePermission(cmd.Context(), name, description)
				if err != nil {
					return fmt.Errorf("creating %s: %w", name, err)
				}
				created = append(created, p)
				a.info("Created permission %s", p.Name)
			}
			if a.jsonOut {
				return a.printJSON(map[string]any{"permissions": created})
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&description, "description", "", "description for the permission(s)")
	return cmd
}

func (a *App) permissionsUpdate() *cobra.Command {
	var description, rename string
	cmd := &cobra.Command{
		Use:   "update <name>",
		Short: "Change a permission's description or name",
		Long: `Change a permission's description and/or rename it. Flags you leave out keep
their current value.`,
		Example: `  permio permissions update document.read --description "Read any document"
  permio permissions update doc.read --rename document.read`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !cmd.Flags().Changed("description") && rename == "" {
				return usageErr("nothing to change: give --description and/or --rename")
			}
			c, _, err := a.client("")
			if err != nil {
				return err
			}
			defer c.Close()
			if !cmd.Flags().Changed("description") {
				cur, err := c.GetPermission(cmd.Context(), args[0])
				if err != nil {
					return err
				}
				description = cur.Description
			}
			p, err := c.UpdatePermission(cmd.Context(), args[0], rename, description)
			if err != nil {
				return err
			}
			if a.jsonOut {
				return a.printJSON(p)
			}
			a.info("Updated permission %s", p.Name)
			return nil
		},
	}
	cmd.Flags().StringVar(&description, "description", "", "new description")
	cmd.Flags().StringVar(&rename, "rename", "", "new name")
	return cmd
}

func (a *App) permissionsDelete() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <name...>",
		Short: "Delete one or more permissions",
		Long: `Delete permissions. Deleting a permission that does not exist succeeds.
Remove a permission from roles before deleting it (roles that still name a
deleted permission cannot be deleted).`,
		Example: `  permio permissions delete document.delete`,
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, _, err := a.client("")
			if err != nil {
				return err
			}
			defer c.Close()
			for _, name := range args {
				if err := c.DeletePermission(cmd.Context(), name); err != nil {
					return fmt.Errorf("deleting %s: %w", name, err)
				}
				a.info("Deleted permission %s", name)
			}
			if a.jsonOut {
				return a.printJSON(map[string]any{"deleted": args})
			}
			return nil
		},
	}
}
