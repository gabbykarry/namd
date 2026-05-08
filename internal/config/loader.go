package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// DefaultFallbackPool is the ordered list of free domains namd tries
// when a user has no custom domain and no subdomain configured.
//
// Why a package-level variable and not hardcoded inside a function?
// Because tests need to override it. And future contributors can
// add domains to this list via a PR without touching logic.
//
// Order matters — we try top to bottom. First working domain wins.
// "working" means: DNS resolves + wildcard cert is obtainable.
var DefaultFallbackPool = []string{
	"namd.africa",   // our own — always first priority
	"namd.is-a.dev", // is-a.dev — free subdomain service for devs
	"loca.lt",       // localtonet free tier
	"serveo.net",    // serveo free tier
}

// Load is the single entry point for reading namd.yml.
//
// It does four things in order:
//  1. Read the file from disk into raw bytes
//  2. Substitute ${ENV_VAR} placeholders with real env values
//  3. Parse the YAML bytes into a Config struct
//  4. Validate and apply defaults to the parsed config
//
// It returns *Config (a pointer) not Config (a value).
//
// Why a pointer?
// Config is a large struct — it contains nested structs, maps, slices.
// If we returned Config by value, Go would COPY the entire struct
// every time you passed it to another function. That is wasteful.
// A pointer (*Config) is just a memory address — 8 bytes on 64-bit systems.
// Cheap to pass around. Every package that needs config receives *Config.
//
// The second return value is error.
// Go has no exceptions. Functions signal failure by returning an error value.
// Callers ALWAYS check: if err != nil { ... }
// nil error = success. Non-nil error = something went wrong.
//
// path is the file path to namd.yml.
// Typically "namd.yml" in the current directory.
// The CLI will pass this in — usually from a --config flag.
func Load(path string) (*Config, error) {
	// ── Step 1: Read the file ────────────────────────────────────────────────

	// os.ReadFile reads the entire file into memory as []byte.
	// []byte is a "slice of bytes" — the raw binary content of the file.
	// YAML is text so these bytes are UTF-8 characters.
	//
	// If the file does not exist, or we lack permission to read it,
	// err is non-nil and raw is nil. We wrap the error with context
	// so the user knows WHICH file failed, not just "file not found".
	raw, err := os.ReadFile(path)
	if err != nil {
		// fmt.Errorf creates a new error with a formatted message.
		// %s = insert the path string
		// %w = WRAP the original err
		//
		// Wrapping (%w) is important. It lets callers do:
		//   errors.Is(err, os.ErrNotExist)
		// to check the underlying cause without string matching.
		// Always wrap errors — always add context about WHERE it happened.
		return nil, fmt.Errorf("config: cannot read %s: %w", path, err)
	}

	// ── Step 2: Substitute environment variables ─────────────────────────────

	// os.ExpandEnv takes a string and replaces every ${VAR} or $VAR
	// with the value of that environment variable.
	//
	// Example: if NAMD_TOKEN=secret123 in the environment, then
	// "token: ${NAMD_TOKEN}" becomes "token: secret123"
	//
	// WHY do this before parsing YAML?
	// If we parsed first and substituted after, the YAML parser would
	// see "${NAMD_TOKEN}" as a literal string value — not a placeholder.
	// We must expand BEFORE parsing so the parser sees the real values.
	//
	// string(raw) converts []byte to string.
	// os.ExpandEnv returns a string.
	// We convert back to []byte for the YAML parser below.
	expanded := os.ExpandEnv(string(raw))

	// ── Step 3: Parse YAML ───────────────────────────────────────────────────

	// var cfg Config declares a Config variable.
	// In Go, a declared variable is automatically set to its "zero value":
	//   string  → ""
	//   int     → 0
	//   bool    → false
	//   map     → nil
	//   slice   → nil
	//   struct  → all fields zero-valued recursively
	//
	// This means cfg starts as a fully zeroed Config struct —
	// every field empty, waiting to be filled by the parser.
	var cfg Config

	// yaml.Unmarshal reads the YAML bytes and fills in our struct.
	//
	// We pass []byte(expanded) — converting our expanded string back to bytes.
	// We pass &cfg — the ADDRESS of cfg, not cfg itself.
	//
	// WHY &cfg and not cfg?
	// yaml.Unmarshal needs to WRITE into cfg — modify its fields.
	// In Go, function arguments are passed by value — Unmarshal
	// would receive a COPY of cfg, fill the copy, then discard it.
	// Our original cfg would stay empty.
	// By passing &cfg (the address), Unmarshal can modify the original.
	// This is the pointer pattern for "output parameters" in Go.
	if err := yaml.Unmarshal([]byte(expanded), &cfg); err != nil {
		return nil, fmt.Errorf("config: invalid YAML in %s: %w", path, err)
	}

	// ── Step 4: Validate and apply defaults ──────────────────────────────────

	// validate is defined in validator.go.
	// It checks required fields, validates formats, and sets defaults.
	// It receives *Config (pointer) so it can MODIFY cfg in place
	// when setting defaults (e.g. Dashboard.Port = 5555).
	//
	// validate is unexported (lowercase v) — it is an implementation
	// detail of the config package. Callers outside this package
	// only ever call Load(). They never call validate() directly.
	if err := validate(&cfg); err != nil {
		return nil, err
	}

	// &cfg returns the memory address of our local cfg variable.
	// We return a pointer — caller gets a reference, not a copy.
	// nil error signals success.
	return &cfg, nil
}
