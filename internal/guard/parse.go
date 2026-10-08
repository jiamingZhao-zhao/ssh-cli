package guard

import (
	"fmt"
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
}

var shellNames = map[string]bool{
	"sh": true, "bash": true, "dash": true, "zsh": true, "ksh": true,
	"ash": true, "csh": true, "tcsh": true, "fish": true,
}

func parseScript(src string) (*parsed, error) {
	parser := syntax.NewParser(syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(src), "")
	if err != nil {
		return nil, err
	}
	p := &parsed{}
	for _, st := range file.Stmts {
		p.stmt(st)
	}
	return p, nil
}

func (p *parsed) feed(src string) {
	inner, err := parseScript(src)
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
		if r.Op == syntax.RdrOut || r.Op == syntax.AppOut || r.Op == syntax.RdrAll || r.Op == syntax.AppAll {
			if r.Word != nil {
				if arg, _ := p.evalOnly(r.Word); arg.Static {
					p.commands = append(p.commands, command{args: []Arg{{Static: true, Value: "redirect"}, arg}})
				}
			}
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
		rest, ok := unwrapWrappers(args)
		if !ok || len(rest) == 0 || !rest[0].Static {
			return "", false
		}
		return rest[0].Value, true
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
	rest, ok := unwrapWrappers(args)
	if !ok {
		p.noteDynamic("could not unwrap sudo/command/exec because an argument is dynamic")
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
	if script, isShell, dynamic := shellScript(rest); isShell {
		if dynamic {
			p.noteDynamic("shell invocation whose script is not a static literal")
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
	return literalWord(w)
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
	var walk func(parts []syntax.WordPart)
	walk = func(parts []syntax.WordPart) {
		for _, part := range parts {
			switch v := part.(type) {
			case *syntax.Lit:
				b.WriteString(v.Value)
			case *syntax.SglQuoted:
				b.WriteString(v.Value)
			case *syntax.DblQuoted:
				walk(v.Parts)
			case *syntax.ProcSubst:
				static = false
				proc = true
			default:
				static = false
			}
		}
	}
	walk(w.Parts)
	if !static {
		return Arg{Static: false}, proc
	}
	return Arg{Static: true, Value: b.String()}, proc
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

func unwrapWrappers(args []Arg) ([]Arg, bool) {
	rest := args
	for i := 0; i < 6 && len(rest) > 0 && rest[0].Static; i++ {
		switch rest[0].Value {
		case "sudo":
			next, ok := stripSudo(rest)
			if !ok {
				return nil, false
			}
			rest = next
		case "command":
			next, ok := stripCommand(rest)
			if !ok {
				return nil, false
			}
			rest = next
		case "exec":
			next, ok := stripExec(rest)
			if !ok {
				return nil, false
			}
			rest = next
		default:
			return rest, true
		}
	}
	return rest, true
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

func shellScript(args []Arg) (script string, isShell, dynamic bool) {
	if len(args) == 0 || !args[0].Static || !shellNames[args[0].Value] {
		return "", false, false
	}
	for i := 1; i < len(args); i++ {
		if !args[i].Static {
			return "", true, true
		}
		switch args[i].Value {
		case "-c", "--command":
			if i+1 >= len(args) || !args[i+1].Static {
				return "", true, true
			}
			return args[i+1].Value, true, false
		}
	}
	return "", true, true
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
