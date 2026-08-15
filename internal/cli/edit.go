package cli

import (
	"encoding/base64"
	"fmt"
	"time"

	"github.com/ivanperez/cli-secret/internal/crypto"
	"github.com/ivanperez/cli-secret/internal/vault"
)

func cmdUpdate(args []string) int {
	fs := newFlagSet("update PROJECT NAME VALUE")
	cfgFlag := fs.String("config", "", "path to config file")
	if !fsParse(fs, args) {
		return 2
	}
	if fs.NArg() < 3 {
		return failUsage("sec update PROJECT NAME VALUE")
	}
	project, name, value := fs.Arg(0), fs.Arg(1), fs.Arg(2)
	if value == "-" {
		b, err := readAllStdin()
		if err != nil {
			return fail(err)
		}
		value = string(b)
	}
	v, _, err := openVault(*cfgFlag)
	if err != nil {
		return fail(err)
	}
	defer v.Close()
	_, err = v.Update(project, name, vault.SecretInput{Project: project, Name: name, Value: value})
	audit(v, "cli", "update", project, name, err)
	if err != nil {
		return fail(err)
	}
	fmt.Printf("Updated %s/%s\n", project, name)
	return 0
}

func cmdRm(args []string) int {
	fs := newFlagSet("rm PROJECT NAME")
	cfgFlag := fs.String("config", "", "path to config file")
	force := fs.Bool("force", false, "do not ask for confirmation")
	if !fsParse(fs, args) {
		return 2
	}
	if fs.NArg() < 2 {
		return failUsage("sec rm PROJECT NAME [--force]")
	}
	project, name := fs.Arg(0), fs.Arg(1)
	if !*force {
		fmt.Printf("Delete %s/%s? [y/N] ", project, name)
		var resp string
		if _, err := fmt.Scanln(&resp); err != nil || (resp != "y" && resp != "Y") {
			fmt.Println("aborted")
			return 0
		}
	}
	v, _, err := openVault(*cfgFlag)
	if err != nil {
		return fail(err)
	}
	defer v.Close()
	err = v.Delete(project, name)
	audit(v, "cli", "delete", project, name, err)
	if err != nil {
		return fail(err)
	}
	fmt.Printf("Deleted %s/%s\n", project, name)
	return 0
}

func cmdRotate(args []string) int {
	fs := newFlagSet("rotate PROJECT NAME")
	cfgFlag := fs.String("config", "", "path to config file")
	random := fs.Bool("random", false, "generate a random value (32 bytes)")
	length := fs.Int("length", 32, "length in bytes when using --random")
	if !fsParse(fs, args) {
		return 2
	}
	if fs.NArg() < 2 {
		return failUsage("sec rotate PROJECT NAME [--random] [--length N]")
	}
	project, name := fs.Arg(0), fs.Arg(1)
	var newValue string
	if *random {
		b, err := crypto.RandomBytes(*length)
		if err != nil {
			return fail(err)
		}
		newValue = base64.RawURLEncoding.EncodeToString(b)
	} else {
		v, _, err := openVault(*cfgFlag)
		if err != nil {
			return fail(err)
		}
		existing, gerr := v.Get(project, name)
		v.Close()
		if gerr != nil {
			return fail(gerr)
		}
		fmt.Printf("Current value: %s\n", existing.Value)
		pass, err := promptPassword("New value: ")
		if err != nil {
			return fail(err)
		}
		newValue = pass
	}
	v, _, err := openVault(*cfgFlag)
	if err != nil {
		return fail(err)
	}
	defer v.Close()
	_, err = v.Rotate(project, name, newValue)
	audit(v, "cli", "rotate", project, name, err)
	if err != nil {
		return fail(err)
	}
	fmt.Printf("Rotated %s/%s (previous version kept)\n", project, name)
	return 0
}

func cmdRollback(args []string) int {
	fs := newFlagSet("rollback PROJECT NAME --version N")
	cfgFlag := fs.String("config", "", "path to config file")
	version := fs.Int("version", 0, "version to restore (required)")
	if !fsParse(fs, args) {
		return 2
	}
	if fs.NArg() < 2 || *version <= 0 {
		return failUsage("sec rollback PROJECT NAME --version N")
	}
	project, name := fs.Arg(0), fs.Arg(1)
	v, _, err := openVault(*cfgFlag)
	if err != nil {
		return fail(err)
	}
	defer v.Close()
	_, err = v.Rollback(project, name, *version)
	audit(v, "cli", "rollback", project, name, err)
	if err != nil {
		return fail(err)
	}
	fmt.Printf("Rolled back %s/%s to version %d\n", project, name, *version)
	return 0
}

func cmdVersions(args []string) int {
	fs := newFlagSet("versions PROJECT NAME")
	cfgFlag := fs.String("config", "", "path to config file")
	if !fsParse(fs, args) {
		return 2
	}
	if fs.NArg() < 2 {
		return failUsage("sec versions PROJECT NAME")
	}
	project, name := fs.Arg(0), fs.Arg(1)
	v, _, err := openVault(*cfgFlag)
	if err != nil {
		return fail(err)
	}
	defer v.Close()
	versions, err := v.Versions(project, name)
	if err != nil {
		return fail(err)
	}
	for _, s := range versions {
		fmt.Printf("v%d  %s  %q\n", s.Version, s.CreatedAt.Format(time.RFC3339), s.Value)
	}
	return 0
}

func cmdRotateMaster(args []string) int {
	fs := newFlagSet("rotate-master")
	cfgFlag := fs.String("config", "", "path to config file")
	if !fsParse(fs, args) {
		return 2
	}
	pass, err := newMasterPassword()
	if err != nil {
		return fail(err)
	}
	v, _, err := openVault(*cfgFlag)
	if err != nil {
		return fail(err)
	}
	defer v.Close()
	if err := v.RotateMaster(pass); err != nil {
		return fail(err)
	}
	audit(v, "cli", "rotate-master", "", "", nil)
	fmt.Println("Master password updated.")
	return 0
}
