package guard

import (
	"fmt"
	"path"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// Arg is one shell word. Static is false when the word contains an expansion.
type Arg struct {
	Static bool
	Value  string
}

func (a Arg) String() string {
	if a.Static {
		return a.Value
	}
	return "<dynamic>"
}

type command struct {
	args []Arg
}

type parsed struct {
	commands   []command
	obfuscated string
	dynamic    string
	// unresolved means the real command cannot be seen. Readonly denies it.
	// Standard and admin require confirmation instead of allowing it.
	unresolved string
	depth      int
}

const maxShellDepth = 6
const maxWrapDepth = 6

type unwrapKind int

const (
	unwrapOK unwrapKind = iota
	unwrapDynamic
	unwrapUnresolved
)

var shellNames = map[string]bool{
	"sh": true, "bash": true, "dash": true, "zsh": true, "ksh": true,
	"ash": true, "csh": true, "tcsh": true, "fish": true,
}

func parseScript(src string) (*parsed, error) {
	return parseScriptAt(src, 0)
}

func parseScriptAt(src string, depth int) (*parsed, error) {
	if depth > maxShellDepth {
		return &parsed{unresolved: "nested shell exceeded depth limit", depth: depth}, nil
	}
	parser := syntax.NewParser(syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(src), "")
	if err != nil {
		return nil, err
	}
	p := &parsed{depth: depth}
	for _, st := range file.Stmts {
		p.stmt(st)
	}
	return p, nil
}

func (p *parsed) feed(src string) {
	inner, err := parseScriptAt(src, p.depth+1)
	if err != nil {
		if p.dynamic == "" {
			p.dynamic = "nested shell script did not parse"
		}
		return
	}
	p.commands = append(p.commands, inner.commands...)
	if p.obfuscated == "" {
		p.obfuscated = inner.obfuscated
	}
	if p.dynamic == "" {
		p.dynamic = inner.dynamic
	}
	if inner.unresolved != "" {
		p.noteUnresolved(inner.unresolved)
	}
}

func (p *parsed) stmt(s *syntax.Stmt) {
	if s == nil || s.Cmd == nil {
		return
	}
	if _, ok := s.Cmd.(*syntax.BinaryCmd); ok {
		if op, isPipe := pipeOp(s); isPipe && (op == syntax.Pipe || op == syntax.PipeAll) {
			stages := flattenPipe(s)
			for i, stage := range stages {
				if i == 0 {
					continue
				}
				if name, ok := entryCommandName(stage); ok && shellNames[name] {
					p.noteObfuscated("pipe into shell (" + name + ")")
				}
			}
		}
	}
	p.walkCommand(s.Cmd)
	for _, r := range s.Redirs {
		if r == nil {
			continue
		}
		if r.Word != nil {
			p.word(r.Word)
		}
		if r.Hdoc != nil {
			p.word(r.Hdoc)
		}
		if isWriteRedirect(r.Op) {
			arg := Arg{}
			if r.Word != nil {
				arg, _ = p.evalOnly(r.Word)
			}
			p.commands = append(p.commands, command{args: []Arg{{Static: true, Value: "redirect"}, arg}})
		}
	}
}

func pipeOp(s *syntax.Stmt) (syntax.BinCmdOperator, bool) {
	b, ok := s.Cmd.(*syntax.BinaryCmd)
	if !ok {
		return 0, false
	}
	return b.Op, true
}

func flattenPipe(s *syntax.Stmt) []*syntax.Stmt {
	b, ok := s.Cmd.(*syntax.BinaryCmd)
	if !ok || (b.Op != syntax.Pipe && b.Op != syntax.PipeAll) {
		return []*syntax.Stmt{s}
	}
	return append(flattenPipe(b.X), flattenPipe(b.Y)...)
}

func entryCommandName(s *syntax.Stmt) (string, bool) {
	if s == nil || s.Cmd == nil {
		return "", false
	}
	switch c := s.Cmd.(type) {
	case *syntax.CallExpr:
		args := make([]Arg, 0, len(c.Args))
		for _, w := range c.Args {
			arg, _ := literalWord(w)
			args = append(args, arg)
		}
		rest, kind, _ := unwrapWrappers(args)
		if kind != unwrapOK || len(rest) == 0 || !rest[0].Static {
			return "", false
		}
		base, _ := commandIdentity(rest[0].Value)
		return base, true
	case *syntax.Subshell:
		if len(c.Stmts) > 0 {
			return entryCommandName(c.Stmts[0])
		}
	case *syntax.Block:
		if len(c.Stmts) > 0 {
			return entryCommandName(c.Stmts[0])
		}
	}
	return "", false
}

func (p *parsed) walkCommand(cmd syntax.Command) {
	if cmd == nil {
		return
	}
	switch c := cmd.(type) {
	case *syntax.CallExpr:
		p.call(c)
	case *syntax.BinaryCmd:
		p.stmt(c.X)
		p.stmt(c.Y)
	case *syntax.IfClause:
		for _, st := range c.Cond {
			p.stmt(st)
		}
		for _, st := range c.Then {
			p.stmt(st)
		}
		if c.Else != nil {
			p.walkCommand(c.Else)
		}
	case *syntax.WhileClause:
		for _, st := range c.Cond {
			p.stmt(st)
		}
		for _, st := range c.Do {
			p.stmt(st)
		}
	case *syntax.ForClause:
		if w, ok := c.Loop.(*syntax.WordIter); ok {
			for _, item := range w.Items {
				p.word(item)
			}
		}
		for _, st := range c.Do {
			p.stmt(st)
		}
	case *syntax.CaseClause:
		p.word(c.Word)
		for _, item := range c.Items {
			for _, pat := range item.Patterns {
				p.word(pat)
			}
			for _, st := range item.Stmts {
				p.stmt(st)
			}
		}
	case *syntax.Block:
		for _, st := range c.Stmts {
			p.stmt(st)
		}
	case *syntax.Subshell:
		for _, st := range c.Stmts {
			p.stmt(st)
		}
	case *syntax.FuncDecl:
		p.stmt(c.Body)
	case *syntax.TimeClause:
		p.stmt(c.Stmt)
	case *syntax.CoprocClause:
		p.word(c.Name)
		p.stmt(c.Stmt)
	case *syntax.TestDecl:
		p.word(c.Description)
		p.stmt(c.Body)
	case *syntax.DeclClause:
		for _, as := range c.Args {
			p.assign(as)
		}
	case *syntax.LetClause:
		for _, ex := range c.Exprs {
			p.arith(ex)
		}
	case *syntax.ArithmCmd:
		p.arith(c.X)
	case *syntax.TestClause:
		p.testExpr(c.X)
	default:
		p.noteDynamic(fmt.Sprintf("unhandled shell construct %T", cmd))
	}
}

func (p *parsed) call(call *syntax.CallExpr) {
	for _, as := range call.Assigns {
		p.assign(as)
	}
	args := make([]Arg, 0, len(call.Args))
	proc := false
	for _, w := range call.Args {
		arg, pr := p.word(w)
		args = append(args, arg)
		proc = proc || pr
	}
	if len(args) == 0 {
		return
	}
	rest, kind, why := unwrapWrappers(args)
	switch kind {
	case unwrapDynamic:
		p.noteDynamic("could not unwrap a command wrapper because an argument is dynamic")
		return
	case unwrapUnresolved:
		p.noteUnresolved(why)
		return
	}
	if len(rest) == 0 {
		return
	}
	if rest[0].Static && rest[0].Value == "eval" {
		p.noteObfuscated("eval")
		if len(rest) >= 2 && rest[1].Static {
			p.feed(rest[1].Value)
		} else if len(rest) >= 2 {
			p.noteDynamic("eval argument is not a static literal")
		}
		return
	}
	if rest[0].Static && (rest[0].Value == "source" || rest[0].Value == ".") && proc {
		p.noteObfuscated("source of a process substitution")
	}
	if script, isShell, skind, swhy := shellScript(rest); isShell {
		switch skind {
		case unwrapUnresolved:
			p.noteUnresolved(swhy)
			return
		case unwrapDynamic:
			p.noteDynamic(swhy)
			return
		}
		p.feed(script)
		return
	}
	p.commands = append(p.commands, command{args: rest})
}

func (p *parsed) assign(as *syntax.Assign) {
	if as == nil {
		return
	}
	if as.Value != nil {
		p.word(as.Value)
	}
	if as.Array != nil {
		for _, el := range as.Array.Elems {
			if el != nil && el.Value != nil {
				p.word(el.Value)
			}
		}
	}
}

// word evaluates w and walks any nested command or process substitutions.
func (p *parsed) word(w *syntax.Word) (Arg, bool) {
	if w == nil {
		return Arg{}, false
	}
	p.walkParts(w.Parts)
	if ansiCEscape(w) {
		p.noteUnresolved("ANSI-C quote cannot be parsed reliably")
	}
	return literalWord(w)
}

func ansiCEscape(w *syntax.Word) bool {
	if w == nil {
		return false
	}
	var hit bool
	var walk func(parts []syntax.WordPart)
	walk = func(parts []syntax.WordPart) {
		for _, part := range parts {
			switch v := part.(type) {
			case *syntax.SglQuoted:
				if v.Dollar && strings.Contains(v.Value, "\\") {
					hit = true
				}
			case *syntax.DblQuoted:
				walk(v.Parts)
			}
		}
	}
	walk(w.Parts)
	return hit
}

// evalOnly extracts a literal without walking, used when walk already happened.
func (p *parsed) evalOnly(w *syntax.Word) (Arg, bool) {
	return literalWord(w)
}

func (p *parsed) walkParts(parts []syntax.WordPart) {
	for _, part := range parts {
		switch v := part.(type) {
		case *syntax.DblQuoted:
			p.walkParts(v.Parts)
		case *syntax.CmdSubst:
			for _, st := range v.Stmts {
				p.stmt(st)
			}
		case *syntax.ProcSubst:
			for _, st := range v.Stmts {
				p.stmt(st)
			}
		case *syntax.ParamExp:
			if v.Exp != nil && v.Exp.Word != nil {
				p.word(v.Exp.Word)
			}
		case *syntax.ArithmExp:
			p.arith(v.X)
		}
	}
}

func literalWord(w *syntax.Word) (Arg, bool) {
	if w == nil {
		return Arg{}, false
	}
	var b strings.Builder
	static := true
	proc := false
	var walk func(parts []syntax.WordPart, doubleQuoted bool)
	walk = func(parts []syntax.WordPart, doubleQuoted bool) {
		for _, part := range parts {
			switch v := part.(type) {
			case *syntax.Lit:
				s, ok := unescapeShellLit(v.Value, doubleQuoted)
				if !ok {
					static = false
					continue
				}
				b.WriteString(s)
			case *syntax.SglQuoted:
				if v.Dollar && strings.Contains(v.Value, "\\") {
					static = false
					continue
				}
				b.WriteString(v.Value)
			case *syntax.DblQuoted:
				walk(v.Parts, true)
			case *syntax.ProcSubst:
				static = false
				proc = true
			default:
				static = false
			}
		}
	}
	walk(w.Parts, false)
	if !static {
		return Arg{Static: false}, proc
	}
	return Arg{Static: true, Value: b.String()}, proc
}

// unescapeShellLit removes shell backslash escapes so a nested script is the
// text the shell will execute. Unquoted escapes consume the next byte.
// Double quotes only consume \, $, `, ", and a newline. A dangling unquoted
// backslash is not a reliable literal.
func unescapeShellLit(value string, doubleQuoted bool) (string, bool) {
	if !strings.Contains(value, "\\") {
		return value, true
	}
	var b strings.Builder
	b.Grow(len(value))
	for i := 0; i < len(value); i++ {
		if value[i] != '\\' {
			b.WriteByte(value[i])
			continue
		}
		if i+1 >= len(value) {
			if doubleQuoted {
				b.WriteByte('\\')
				return b.String(), true
			}
			return "", false
		}
		n := value[i+1]
		if doubleQuoted {
			switch n {
			case '$', '`', '"', '\\', '\n':
				if n != '\n' {
					b.WriteByte(n)
				}
				i++
			default:
				b.WriteByte('\\')
			}
			continue
		}
		if n != '\n' {
			b.WriteByte(n)
		}
		i++
	}
	return b.String(), true
}

func (p *parsed) noteObfuscated(why string) {
	if p.obfuscated == "" {
		p.obfuscated = why
	}
}

func (p *parsed) noteDynamic(why string) {
	if p.dynamic == "" {
		p.dynamic = why
	}
}

func (p *parsed) noteUnresolved(why string) {
	if p.unresolved == "" {
		p.unresolved = why
	}
}

var wrapperNames = map[string]bool{
	"sudo": true, "command": true, "exec": true, "env": true,
	"nohup": true, "nice": true, "timeout": true, "stdbuf": true, "xargs": true,
	"ionice": true, "chrt": true, "taskset": true, "setsid": true, "flock": true, "watch": true,
}

// opaqueWrappers hide the real command behind an option grammar that is not
// expanded here. standard confirms them and readonly denies them.
var opaqueWrappers = map[string]bool{
	"ionice": true, "chrt": true, "taskset": true, "setsid": true, "flock": true, "watch": true,
}

// commandIdentity splits argv0 into a basename and whether that path is a
// trusted wrapper location. Bare names stay trusted so PATH lookups keep
// working. Allow-list checks still see the original argv0.
func commandIdentity(argv0 string) (base string, trusted bool) {
	if argv0 == "" || strings.Contains(argv0, "\\") {
		return argv0, false
	}
	if !strings.Contains(argv0, "/") {
		return argv0, true
	}
	base = path.Base(argv0)
	switch path.Dir(argv0) {
	case "/bin", "/usr/bin", "/usr/local/bin", "/sbin", "/usr/sbin":
		return base, true
	default:
		return base, false
	}
}

func unwrapWrappers(args []Arg) ([]Arg, unwrapKind, string) {
	rest := args
	for i := 0; i < maxWrapDepth; i++ {
		if len(rest) == 0 {
			return rest, unwrapOK, ""
		}
		if !rest[0].Static {
			return nil, unwrapDynamic, ""
		}
		base, trusted := commandIdentity(rest[0].Value)
		if shellNames[base] && !trusted {
			return nil, unwrapUnresolved, "untrusted shell path " + rest[0].Value
		}
		if base == "find" {
			if findMayExec(rest) {
				return nil, unwrapUnresolved, "find -exec cannot be expanded safely"
			}
			return rest, unwrapOK, ""
		}
		if !wrapperNames[base] {
			return rest, unwrapOK, ""
		}
		if !trusted {
			return nil, unwrapUnresolved, "untrusted wrapper path " + rest[0].Value
		}
		if opaqueWrappers[base] {
			return nil, unwrapUnresolved, base + " wrapper is not expanded"
		}
		var next []Arg
		var kind unwrapKind
		var why string
		switch base {
		case "sudo":
			var ok bool
			next, ok = stripSudo(rest)
			if !ok {
				kind = unwrapDynamic
			}
		case "command":
			var ok bool
			next, ok = stripCommand(rest)
			if !ok {
				kind = unwrapDynamic
			}
		case "exec":
			var ok bool
			next, ok = stripExec(rest)
			if !ok {
				kind = unwrapDynamic
			}
		case "env":
			next, kind, why = stripEnv(rest)
		case "nohup":
			next, kind, why = stripNohup(rest)
		case "nice":
			next, kind, why = stripNice(rest)
		case "timeout":
			next, kind, why = stripTimeout(rest)
		case "stdbuf":
			next, kind, why = stripStdbuf(rest)
		case "xargs":
			next, kind, why = stripXargs(rest)
		default:
			return rest, unwrapOK, ""
		}
		if kind != unwrapOK {
			if why == "" {
				why = "command wrapper could not be resolved"
			}
			return nil, kind, why
		}
		rest = next
	}
	if len(rest) > 0 && rest[0].Static {
		base, _ := commandIdentity(rest[0].Value)
		if wrapperNames[base] || shellNames[base] {
			return nil, unwrapUnresolved, "nested wrappers exceeded depth limit"
		}
	}
	return rest, unwrapOK, ""
}

func stripSudo(args []Arg) ([]Arg, bool) {
	i := 1
	for i < len(args) {
		a := args[i]
		if !a.Static {
			return nil, false
		}
		if a.Value == "--" {
			return args[i+1:], true
		}
		if a.Value == "-" || !strings.HasPrefix(a.Value, "-") {
			return args[i:], true
		}
		if strings.HasPrefix(a.Value, "--") {
			name, _, hasEq := strings.Cut(a.Value, "=")
			if longTakesArg(name) && !hasEq {
				if i+1 >= len(args) {
					return nil, false
				}
				i += 2
				continue
			}
			i++
			continue
		}
		chars := a.Value[1:]
		consumedArg := false
		for j := 0; j < len(chars); j++ {
			if shortTakesArg(chars[j]) {
				if j+1 < len(chars) {
					i++
				} else {
					if i+1 >= len(args) {
						return nil, false
					}
					i += 2
				}
				consumedArg = true
				break
			}
		}
		if !consumedArg {
			i++
		}
	}
	return args[i:], true
}

func longTakesArg(name string) bool {
	switch name {
	case "--user", "--group", "--prompt", "--close-from", "--chdir", "--host", "--role", "--type", "--other-user", "--command-timeout":
		return true
	default:
		return false
	}
}

func shortTakesArg(c byte) bool {
	switch c {
	case 'u', 'g', 'p', 'C', 'D', 'h', 'r', 't', 'U', 'T':
		return true
	default:
		return false
	}
}

func stripCommand(args []Arg) ([]Arg, bool) {
	i := 1
	for i < len(args) {
		a := args[i]
		if !a.Static {
			return nil, false
		}
		if a.Value == "--" {
			return args[i+1:], true
		}
		if a.Value == "-p" || a.Value == "-v" || a.Value == "-V" {
			i++
			continue
		}
		break
	}
	return args[i:], true
}

func isWriteRedirect(op syntax.RedirOperator) bool {
	switch op {
	case syntax.RdrOut, syntax.AppOut, syntax.RdrAll, syntax.AppAll, syntax.RdrInOut, syntax.ClbOut:
		return true
	default:
		return false
	}
}

func stripEnv(args []Arg) ([]Arg, unwrapKind, string) {
	i := 1
	for i < len(args) {
		a := args[i]
		if !a.Static {
			return nil, unwrapDynamic, ""
		}
		v := a.Value
		switch {
		case v == "--":
			return args[i+1:], unwrapOK, ""
		case v == "-":
			i++
		case !strings.HasPrefix(v, "-"):
			if strings.Contains(v, "=") {
				i++
				continue
			}
			return args[i:], unwrapOK, ""
		case strings.HasPrefix(v, "--"):
			name, val, hasEq := strings.Cut(v, "=")
			switch name {
			case "--ignore-environment", "--null", "--debug":
				i++
			case "--unset", "--chdir":
				if hasEq {
					i++
					continue
				}
				if i+1 >= len(args) || !args[i+1].Static {
					return nil, unwrapDynamic, ""
				}
				i += 2
			case "--split-string":
				payload := val
				rest := args[i+1:]
				if !hasEq {
					if i+1 >= len(args) {
						return nil, unwrapUnresolved, "env -S command string cannot be parsed reliably"
					}
					if !args[i+1].Static {
						return nil, unwrapUnresolved, "env -S command string cannot be parsed reliably"
					}
					payload = args[i+1].Value
					rest = args[i+2:]
				}
				return finishEnvSplit(payload, rest)
			default:
				return nil, unwrapDynamic, ""
			}
		default:
			chars := v[1:]
			advanced := false
			for k := 0; k < len(chars); k++ {
				switch chars[k] {
				case 'i', '0', 'v':
				case 'u', 'C':
					if k+1 < len(chars) {
						i++
					} else {
						if i+1 >= len(args) || !args[i+1].Static {
							return nil, unwrapDynamic, ""
						}
						i += 2
					}
					advanced = true
					k = len(chars)
				case 'S':
					payload := ""
					rest := []Arg{}
					if k+1 < len(chars) {
						payload = chars[k+1:]
						rest = args[i+1:]
					} else {
						if i+1 >= len(args) || !args[i+1].Static {
							return nil, unwrapUnresolved, "env -S command string cannot be parsed reliably"
						}
						payload = args[i+1].Value
						rest = args[i+2:]
					}
					return finishEnvSplit(payload, rest)
				default:
					return nil, unwrapDynamic, ""
				}
			}
			if !advanced {
				i++
			}
		}
	}
	return args[i:], unwrapOK, ""
}

// finishEnvSplit turns a GNU env -S / --split-string payload into the command
// env would execute. Strings that depend on the remote environment, or that
// use escapes this parser does not reproduce, are refused upstream.
func finishEnvSplit(payload string, rest []Arg) ([]Arg, unwrapKind, string) {
	cmd, ok := splitEnvCommand(payload)
	if !ok {
		return nil, unwrapUnresolved, "env -S command string cannot be parsed reliably"
	}
	for _, a := range rest {
		if !a.Static {
			return nil, unwrapUnresolved, "env -S command string cannot be parsed reliably"
		}
	}
	return append(cmd, rest...), unwrapOK, ""
}

// splitEnvCommand splits a static env -S string. It understands quotes and
// comments. $ expansions and backslash escapes are rejected: GNU env expands
// ${VAR} from the remote environment, so those strings are not knowable here.
func splitEnvCommand(s string) ([]Arg, bool) {
	var args []Arg
	var b strings.Builder
	token := false
	inSingle := false
	inDouble := false
	flush := func() {
		if !token {
			return
		}
		args = append(args, Arg{Static: true, Value: b.String()})
		b.Reset()
		token = false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inSingle {
			if c == '\'' {
				inSingle = false
				continue
			}
			b.WriteByte(c)
			token = true
			continue
		}
		if inDouble {
			if c == '"' {
				inDouble = false
				continue
			}
			if c == '$' || c == '\\' || c == '`' {
				return nil, false
			}
			b.WriteByte(c)
			token = true
			continue
		}
		switch c {
		case '\'':
			inSingle = true
			token = true
		case '"':
			inDouble = true
			token = true
		case '$', '\\', '`':
			return nil, false
		case '#':
			if !token {
				if inSingle || inDouble {
					return nil, false
				}
				return args, true
			}
			b.WriteByte(c)
		case ' ', '\t', '\n', '\r':
			flush()
		default:
			b.WriteByte(c)
			token = true
		}
	}
	if inSingle || inDouble {
		return nil, false
	}
	flush()
	return args, true
}

func findMayExec(args []Arg) bool {
	for _, a := range args[1:] {
		if !a.Static {
			return true
		}
		switch a.Value {
		case "-exec", "-execdir", "-ok", "-okdir":
			return true
		}
	}
	return false
}

func stripNohup(args []Arg) ([]Arg, unwrapKind, string) {
	i := 1
	for i < len(args) {
		if !args[i].Static {
			return nil, unwrapUnresolved, "nohup arguments are not static"
		}
		switch args[i].Value {
		case "--":
			return args[i+1:], unwrapOK, ""
		case "--help", "--version":
			i++
		default:
			if strings.HasPrefix(args[i].Value, "-") {
				return nil, unwrapUnresolved, "nohup arguments could not be expanded"
			}
			return args[i:], unwrapOK, ""
		}
	}
	return args[i:], unwrapOK, ""
}

func stripNice(args []Arg) ([]Arg, unwrapKind, string) {
	i := 1
	for i < len(args) {
		if !args[i].Static {
			return nil, unwrapUnresolved, "nice arguments are not static"
		}
		v := args[i].Value
		switch {
		case v == "--":
			return args[i+1:], unwrapOK, ""
		case v == "--help" || v == "--version":
			i++
		case v == "-n" || v == "--adjustment":
			if i+1 >= len(args) || !args[i+1].Static {
				return nil, unwrapUnresolved, "nice arguments could not be expanded"
			}
			i += 2
		case strings.HasPrefix(v, "--adjustment="):
			i++
		case strings.HasPrefix(v, "-") && niceAdjust(v):
			i++
		case strings.HasPrefix(v, "-"):
			return nil, unwrapUnresolved, "nice arguments could not be expanded"
		default:
			return args[i:], unwrapOK, ""
		}
	}
	return args[i:], unwrapOK, ""
}

func niceAdjust(v string) bool {
	body := v[1:]
	body = strings.TrimPrefix(body, "n")
	body = strings.TrimPrefix(body, "+")
	if body == "" {
		return false
	}
	for _, c := range body {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func stripTimeout(args []Arg) ([]Arg, unwrapKind, string) {
	i := 1
	for i < len(args) {
		if !args[i].Static {
			return nil, unwrapUnresolved, "timeout arguments are not static"
		}
		v := args[i].Value
		switch {
		case v == "--":
			if i+2 > len(args) {
				return nil, unwrapUnresolved, "timeout command could not be expanded"
			}
			return args[i+2:], unwrapOK, ""
		case v == "--preserve-status" || v == "--foreground" || v == "--verbose" || v == "-v" || v == "--help" || v == "--version":
			i++
		case v == "-k" || v == "--kill-after" || v == "-s" || v == "--signal":
			if i+1 >= len(args) || !args[i+1].Static {
				return nil, unwrapUnresolved, "timeout arguments could not be expanded"
			}
			i += 2
		case strings.HasPrefix(v, "--kill-after=") || strings.HasPrefix(v, "--signal="):
			i++
		case strings.HasPrefix(v, "-"):
			return nil, unwrapUnresolved, "timeout arguments could not be expanded"
		default:
			return args[i+1:], unwrapOK, ""
		}
	}
	return nil, unwrapUnresolved, "timeout command could not be expanded"
}

func stripStdbuf(args []Arg) ([]Arg, unwrapKind, string) {
	i := 1
	saw := false
	for i < len(args) {
		if !args[i].Static {
			return nil, unwrapUnresolved, "stdbuf arguments are not static"
		}
		v := args[i].Value
		switch {
		case v == "--":
			if !saw {
				return nil, unwrapUnresolved, "stdbuf command could not be expanded"
			}
			return args[i+1:], unwrapOK, ""
		case v == "-i" || v == "-o" || v == "-e":
			if i+1 >= len(args) || !args[i+1].Static {
				return nil, unwrapUnresolved, "stdbuf arguments could not be expanded"
			}
			saw = true
			i += 2
		case strings.HasPrefix(v, "--input=") || strings.HasPrefix(v, "--output=") || strings.HasPrefix(v, "--error="):
			saw = true
			i++
		case strings.HasPrefix(v, "--"):
			return nil, unwrapUnresolved, "stdbuf arguments could not be expanded"
		case strings.HasPrefix(v, "-") && len(v) > 2 && (v[1] == 'i' || v[1] == 'o' || v[1] == 'e'):
			saw = true
			i++
		case strings.HasPrefix(v, "-"):
			return nil, unwrapUnresolved, "stdbuf arguments could not be expanded"
		default:
			if !saw {
				return nil, unwrapUnresolved, "stdbuf command could not be expanded"
			}
			return args[i:], unwrapOK, ""
		}
	}
	return nil, unwrapUnresolved, "stdbuf command could not be expanded"
}

func stripXargs(args []Arg) ([]Arg, unwrapKind, string) {
	i := 1
	for i < len(args) {
		if !args[i].Static {
			return nil, unwrapUnresolved, "xargs arguments are not static"
		}
		v := args[i].Value
		if v == "--" {
			return args[i+1:], unwrapOK, ""
		}
		if !strings.HasPrefix(v, "-") {
			return args[i:], unwrapOK, ""
		}
		if strings.HasPrefix(v, "--") {
			name, _, hasEq := strings.Cut(v, "=")
			switch name {
			case "--null", "--interactive", "--no-run-if-empty", "--verbose", "--exit", "--show-limits", "--help", "--version":
				i++
			case "--arg-file", "--delimiter", "--eof", "--replace", "--max-lines", "--max-args", "--max-procs", "--max-chars", "--process-slot-var":
				if hasEq {
					i++
					continue
				}
				if i+1 >= len(args) || !args[i+1].Static {
					return nil, unwrapUnresolved, "xargs arguments could not be expanded"
				}
				i += 2
			default:
				return nil, unwrapUnresolved, "xargs arguments could not be expanded"
			}
			continue
		}
		chars := v[1:]
		k := 0
		advanced := false
		for k < len(chars) {
			switch chars[k] {
			case '0', 't', 'r', 'x', 'p':
				k++
			case 'a', 'd', 'E', 'I', 'L', 'n', 'P', 's':
				if k+1 < len(chars) {
					i++
					advanced = true
					k = len(chars)
					continue
				}
				if i+1 >= len(args) || !args[i+1].Static {
					return nil, unwrapUnresolved, "xargs arguments could not be expanded"
				}
				i += 2
				advanced = true
				k = len(chars)
			case 'e', 'i', 'l':
				i++
				advanced = true
				k = len(chars)
			default:
				return nil, unwrapUnresolved, "xargs arguments could not be expanded"
			}
		}
		if !advanced {
			i++
		}
	}
	// GNU xargs runs echo when no command is given.
	return []Arg{{Static: true, Value: "echo"}}, unwrapOK, ""
}

func stripExec(args []Arg) ([]Arg, bool) {
	i := 1
	for i < len(args) {
		a := args[i]
		if !a.Static {
			return nil, false
		}
		if a.Value == "--" {
			return args[i+1:], true
		}
		if !strings.HasPrefix(a.Value, "-") {
			return args[i:], true
		}
		if a.Value == "-a" || a.Value == "-c" {
			if i+1 >= len(args) {
				return nil, false
			}
			i += 2
			continue
		}
		i++
	}
	return args[i:], true
}

func shellScript(args []Arg) (script string, isShell bool, kind unwrapKind, why string) {
	if len(args) == 0 || !args[0].Static {
		return "", false, unwrapOK, ""
	}
	base, trusted := commandIdentity(args[0].Value)
	if !shellNames[base] {
		return "", false, unwrapOK, ""
	}
	if !trusted {
		return "", true, unwrapUnresolved, "untrusted shell path " + args[0].Value
	}
	for i := 1; i < len(args); i++ {
		if !args[i].Static {
			return "", true, unwrapDynamic, "shell invocation whose script is not a static literal"
		}
		switch args[i].Value {
		case "-c", "--command":
			if i+1 >= len(args) || !args[i+1].Static {
				return "", true, unwrapDynamic, "shell invocation whose script is not a static literal"
			}
			return args[i+1].Value, true, unwrapOK, ""
		}
	}
	return "", true, unwrapDynamic, "shell invocation whose script is not a static literal"
}

func (p *parsed) arith(ex syntax.ArithmExpr) {
	switch v := ex.(type) {
	case nil:
	case *syntax.Word:
		p.word(v)
	case *syntax.BinaryArithm:
		p.arith(v.X)
		p.arith(v.Y)
	case *syntax.UnaryArithm:
		p.arith(v.X)
	case *syntax.ParenArithm:
		p.arith(v.X)
	}
}

func (p *parsed) testExpr(ex syntax.TestExpr) {
	switch v := ex.(type) {
	case nil:
	case *syntax.Word:
		p.word(v)
	case *syntax.BinaryTest:
		p.testExpr(v.X)
		p.testExpr(v.Y)
	case *syntax.UnaryTest:
		p.testExpr(v.X)
	case *syntax.ParenTest:
		p.testExpr(v.X)
	}
}
