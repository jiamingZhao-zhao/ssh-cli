package guard

import (
	"regexp"
	"strings"
)

// diskPath matches whole-disk device nodes that must never be written.
var diskPath = regexp.MustCompile(`(?i)^/dev/(sd[a-z]|nvme[0-9]|mmcblk[0-9]|hd[a-z]|vd[a-z]|xvd[a-z]|disk)`)

func builtinDeny(args []Arg) string {
	if len(args) == 0 || !args[0].Static {
		return ""
	}
	name := args[0].Value
	switch name {
	case "redirect":
		if len(args) >= 2 && args[1].Static && diskPath.MatchString(args[1].Value) {
			return "redirect onto disk device " + args[1].Value
		}
		return ""
	case "rm":
		if destructiveRM(args) {
			return "rm of filesystem root"
		}
	case "chmod", "chown":
		if operandIsRoot(args) {
			return name + " of filesystem root"
		}
	default:
		if name == "mkfs" || strings.HasPrefix(name, "mkfs.") {
			return "mkfs"
		}
		if name == "dd" && ddToDisk(args) {
			return "dd onto a disk device"
		}
	}
	return ""
}

func destructiveRM(args []Arg) bool {
	recursive := false
	force := false
	var operands []string
	for i := 1; i < len(args); i++ {
		a := args[i]
		if !a.Static {
			if !strings.HasPrefix(a.Value, "-") && a.Value != "" {
				// Dynamic target: only a proven root path is a hard deny.
				continue
			}
			continue
		}
		if a.Value == "--" {
			for _, op := range args[i+1:] {
				if op.Static {
					operands = append(operands, op.Value)
				}
			}
			break
		}
		if strings.HasPrefix(a.Value, "--") {
			switch a.Value {
			case "--recursive":
				recursive = true
			case "--force":
				force = true
			}
			continue
		}
		if strings.HasPrefix(a.Value, "-") && a.Value != "-" {
			flags := a.Value[1:]
			if strings.ContainsAny(flags, "rR") {
				recursive = true
			}
			if strings.Contains(flags, "f") {
				force = true
			}
			continue
		}
		operands = append(operands, a.Value)
	}
	if !(recursive && force) {
		return false
	}
	for _, op := range operands {
		if isRootPath(op) {
			return true
		}
	}
	return false
}

func isRootPath(p string) bool {
	switch p {
	case "/", "/*", "/**", "/.", "/..":
		return true
	default:
		return false
	}
}

func operandIsRoot(args []Arg) bool {
	for i := 1; i < len(args); i++ {
		a := args[i]
		if !a.Static {
			continue
		}
		if a.Value == "--" {
			for _, op := range args[i+1:] {
				if op.Static && isRootPath(op.Value) {
					return true
				}
			}
			return false
		}
		if strings.HasPrefix(a.Value, "-") {
			continue
		}
		if isRootPath(a.Value) {
			return true
		}
	}
	return false
}

func ddToDisk(args []Arg) bool {
	for _, a := range args[1:] {
		if a.Static && diskPath.MatchString(strings.TrimPrefix(a.Value, "of=")) && strings.HasPrefix(a.Value, "of=") {
			return true
		}
	}
	return false
}

func rawCatastrophe(src string) string {
	compact := strings.ReplaceAll(src, " ", "")
	if strings.Contains(compact, ":(){") && strings.Contains(compact, ":|:") {
		return "fork bomb"
	}
	return ""
}

func isForkBomb(src string) bool {
	return rawCatastrophe(src) != ""
}
