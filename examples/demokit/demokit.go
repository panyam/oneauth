// Package demokit provides an interactive step-through framework for OneAuth
// examples. Each example defines a sequence of steps (with mermaid diagram
// arrows) and optional sections (explanatory text). The same definitions
// drive both the interactive CLI and the generated README.
//
// Single source of truth: step titles, arrows, and notes are defined in Go
// code. The README's mermaid diagram and step documentation are generated
// from these definitions — never maintained by hand.
//
// Usage:
//
//	demo := demokit.New("01: Client Credentials Flow").
//	    Description("Non-UI | No infrastructure needed").
//	    Actors(
//	        demokit.Actor("App", "Client App"),
//	        demokit.Actor("AS", "Auth Server"),
//	    )
//	demo.Step("Register a client").
//	    Arrow("App", "AS", "POST /apps/register").
//	    Arrow("AS", "App", "{client_id, client_secret}").
//	    Note("The client gets credentials for later use.").
//	    Run(func() { fmt.Println("registered!") })
//	demo.Execute()
package demokit

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// ActorDef defines a participant in the sequence diagram.
type ActorDef struct {
	ID    string // Short identifier used in arrows (e.g., "AS")
	Label string // Display label (e.g., "Auth Server")
}

// Actor creates an ActorDef.
func Actor(id, label string) ActorDef {
	return ActorDef{ID: id, Label: label}
}

// item is a union type for the ordered sequence of steps and sections.
type item interface {
	isItem()
}

// Ref is a named reference (RFC, CVE, blog post, spec section, etc.).
type Ref struct {
	Name string // e.g., "RFC 7519 (JWT)" or "CVE-2015-9235"
	URL  string // e.g., "https://www.rfc-editor.org/rfc/rfc7519"
}

// StepDef defines one executable step in the demo.
type StepDef struct {
	title  string
	arrows []arrowDef
	refs   []Ref
	note   string
	runFn  func()
}

type arrowDef struct {
	from, to, label string
	dashed          bool // -->> vs ->>
}

func (s *StepDef) isItem() {}

// Arrow adds a solid arrow (request) to the step's sequence diagram.
func (s *StepDef) Arrow(from, to, label string) *StepDef {
	s.arrows = append(s.arrows, arrowDef{from: from, to: to, label: label})
	return s
}

// DashedArrow adds a dashed arrow (response) to the step's sequence diagram.
func (s *StepDef) DashedArrow(from, to, label string) *StepDef {
	s.arrows = append(s.arrows, arrowDef{from: from, to: to, label: label, dashed: true})
	return s
}

// Ref adds a reference (RFC, CVE, spec section, blog post, etc.) to this step.
// Use pre-defined constants from refs.go: demokit.RFC7519, demokit.CVE_2015_9235, etc.
func (s *StepDef) Ref(ref Ref) *StepDef {
	s.refs = append(s.refs, ref)
	return s
}

// Note adds explanatory text shown in both CLI and README.
func (s *StepDef) Note(text string) *StepDef {
	s.note = text
	return s
}

// Run sets the function to execute for this step.
func (s *StepDef) Run(fn func()) *StepDef {
	s.runFn = fn
	return s
}

// SectionDef is a non-executable block of explanatory content.
type SectionDef struct {
	title string
	body  string
}

func (s *SectionDef) isItem() {}

// Demo is the top-level container for an interactive example.
type Demo struct {
	title       string
	description string
	dir         string // directory name for run commands in generated README
	actors      []ActorDef
	items       []item
	stepCount   int
}

// New creates a new Demo with the given title.
func New(title string) *Demo {
	return &Demo{title: title}
}

// Description sets the one-line description shown in the CLI header.
func (d *Demo) Description(desc string) *Demo {
	d.description = desc
	return d
}

// Dir sets the directory name used in generated README run commands.
// e.g., Dir("01-client-credentials") produces "go run ./examples/01-client-credentials/"
func (d *Demo) Dir(name string) *Demo {
	d.dir = name
	return d
}

// Actors sets the sequence diagram participants.
func (d *Demo) Actors(actors ...ActorDef) *Demo {
	d.actors = actors
	return d
}

// Step adds an executable step to the demo. Returns the StepDef for chaining.
func (d *Demo) Step(title string) *StepDef {
	s := &StepDef{title: title}
	d.items = append(d.items, s)
	d.stepCount++
	return s
}

// Section adds a non-executable explanatory block. Lines are joined with
// newlines, so you can write multi-paragraph markdown naturally:
//
//	demo.Section("How it works",
//	    "The auth server signs tokens with HS256.",
//	    "",
//	    "**Key insight:** Both servers share the same KeyStore.",
//	)
func (d *Demo) Section(title string, lines ...string) *Demo {
	d.items = append(d.items, &SectionDef{title: title, body: strings.Join(lines, "\n")})
	return d
}

// Execute runs the demo interactively — pausing between steps for Enter.
// If --non-interactive is passed (or stdin is not a terminal), runs without pausing.
func (d *Demo) Execute() {
	interactive := isTerminal()
	for _, arg := range os.Args[1:] {
		if arg == "--non-interactive" {
			interactive = false
		}
		if arg == "--readme" {
			fmt.Print(d.Markdown())
			return
		}
	}

	// Header
	fmt.Printf("=== %s ===\n", d.title)
	if d.description != "" {
		fmt.Printf("    %s\n", d.description)
	}
	fmt.Printf("    %d steps\n", d.stepCount)
	fmt.Println()

	reader := bufio.NewReader(os.Stdin)
	stepNum := 0

	for _, it := range d.items {
		switch v := it.(type) {
		case *StepDef:
			stepNum++
			// Step header
			fmt.Printf("  Step %d/%d: %s", stepNum, d.stepCount, v.title)
			fmt.Printf("  [README → Step %d]\n", stepNum)

			// References
			if len(v.refs) > 0 {
				fmt.Print("    Refs: ")
				for i, ref := range v.refs {
					if i > 0 {
						fmt.Print(", ")
					}
					fmt.Print(ref.Name)
				}
				fmt.Println()
			}

			// Diagram arrows
			for _, a := range v.arrows {
				arrow := "->>"
				if a.dashed {
					arrow = "-->>"
				}
				fmt.Printf("    %s %s %s: %s\n", a.from, arrow, a.to, a.label)
			}

			// Note
			if v.note != "" {
				fmt.Printf("\n    %s\n", v.note)
			}

			// Pause
			if interactive {
				fmt.Print("\n    Press Enter to run this step...")
				reader.ReadString('\n')
			}
			fmt.Println()

			// Execute
			if v.runFn != nil {
				v.runFn()
			}
			fmt.Println()

		case *SectionDef:
			fmt.Printf("  --- %s ---\n", v.title)
			for _, line := range strings.Split(v.body, "\n") {
				fmt.Printf("    %s\n", line)
			}
			fmt.Println()
		}
	}

	fmt.Println("=== Done ===")
}

// Markdown generates the full README content from the demo definition.
// This is the single source of truth — run with --readme to regenerate.
func (d *Demo) Markdown() string {
	var b strings.Builder

	// Title and description
	fmt.Fprintf(&b, "# %s\n\n", d.title)
	if d.description != "" {
		fmt.Fprintf(&b, "%s\n\n", d.description)
	}

	// Collect steps for the summary
	var steps []*StepDef
	for _, it := range d.items {
		if s, ok := it.(*StepDef); ok {
			steps = append(steps, s)
		}
	}

	// What you'll learn (from step notes)
	hasNotes := false
	for _, s := range steps {
		if s.note != "" {
			hasNotes = true
			break
		}
	}
	if hasNotes {
		b.WriteString("## What you'll learn\n\n")
		for _, s := range steps {
			if s.note != "" {
				fmt.Fprintf(&b, "- **%s** — %s\n", s.title, s.note)
			}
		}
		b.WriteString("\n")
	}

	// Sequence diagram
	b.WriteString("## Flow\n\n```mermaid\nsequenceDiagram\n")
	for _, a := range d.actors {
		if a.ID != a.Label {
			fmt.Fprintf(&b, "    participant %s as %s\n", a.ID, a.Label)
		} else {
			fmt.Fprintf(&b, "    participant %s\n", a.ID)
		}
	}
	stepNum := 0
	for _, it := range d.items {
		switch v := it.(type) {
		case *StepDef:
			stepNum++
			fmt.Fprintf(&b, "\n    Note over %s,%s: Step %d: %s\n",
				d.actors[0].ID, d.actors[len(d.actors)-1].ID, stepNum, v.title)
			for _, a := range v.arrows {
				if a.dashed {
					fmt.Fprintf(&b, "    %s-->>%s: %s\n", a.from, a.to, a.label)
				} else {
					fmt.Fprintf(&b, "    %s->>%s: %s\n", a.from, a.to, a.label)
				}
			}
		}
	}
	b.WriteString("```\n\n")

	// Steps detail
	b.WriteString("## Steps\n\n")
	stepNum = 0
	allRefs := make(map[string]Ref) // dedup by URL
	for _, it := range d.items {
		switch v := it.(type) {
		case *StepDef:
			stepNum++
			fmt.Fprintf(&b, "### Step %d: %s\n\n", stepNum, v.title)
			if len(v.refs) > 0 {
				b.WriteString("> **References:** ")
				for i, ref := range v.refs {
					if i > 0 {
						b.WriteString(", ")
					}
					fmt.Fprintf(&b, "[%s](%s)", ref.Name, ref.URL)
					allRefs[ref.URL] = ref
				}
				b.WriteString("\n\n")
			}
			if v.note != "" {
				fmt.Fprintf(&b, "%s\n\n", v.note)
			}
		case *SectionDef:
			fmt.Fprintf(&b, "### %s\n\n%s\n\n", v.title, v.body)
		}
	}

	// Collected references (deduped)
	if len(allRefs) > 0 {
		b.WriteString("## References\n\n")
		for _, ref := range allRefs {
			fmt.Fprintf(&b, "- [%s](%s)\n", ref.Name, ref.URL)
		}
		b.WriteString("\n")
	}

	// Run command
	dir := d.dir
	if dir == "" {
		dir = "<this-directory>"
	}
	b.WriteString("## Run it\n\n")
	fmt.Fprintf(&b, "```bash\ngo run ./examples/%s/\n```\n\n", dir)
	b.WriteString("Pass `--non-interactive` to skip pauses:\n\n")
	fmt.Fprintf(&b, "```bash\ngo run ./examples/%s/ --non-interactive\n```\n", dir)

	return b.String()
}

// isTerminal returns true if stdin appears to be an interactive terminal.
func isTerminal() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
