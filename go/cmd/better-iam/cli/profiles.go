package cli

// Port of packages/cli/src/profiles.ts.

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"

	"github.com/Better-IAM/better-iam/go/core"
)

// StoredProfile is a signed-in session saved by `better-iam login`, so later commands act as it without
// BETTER_IAM_TOKEN. It belongs to one deployment: a remote endpoint (URL) or the configuration it was created with
// (Config). Its JSON form is the credentials file's (shared with the TypeScript CLI).
type StoredProfile struct {
	// URL is the IAM endpoint (https://host/api/iam) the session was issued by, for remote commands.
	URL string `json:"url,omitempty"`
	// Config is the configuration the session was issued through, for in-process commands.
	Config string `json:"config,omitempty"`
	// EnvConfig: the session was issued through the environment-only deployment (BETTER_IAM_DATABASE_URL, no file).
	EnvConfig  bool   `json:"envConfig,omitempty"`
	TenantID   string `json:"tenantId,omitempty"`
	IdentityID string `json:"identityId,omitempty"`
	Email      string `json:"email,omitempty"`
	// Kind is the session kind: user, api-key, role, or session-token.
	Kind string `json:"kind,omitempty"`
	// Token is the bearer token. The file is written with owner-only permissions; treat it like a password.
	Token string `json:"token"`
	// ExpiresAt is when the session ends (epoch ms), when known.
	ExpiresAt *float64 `json:"expiresAt,omitempty"`
	SavedAt   float64  `json:"savedAt"`
}

// ProfileSummary is a profile as listed by `better-iam profiles`: everything except the token.
type ProfileSummary struct {
	Name    string `json:"name"`
	Current bool   `json:"current"`
	// Record is the saved profile without its token, in the file's member order.
	Record *core.Object `json:"-"`
}

// Model is the summary as printed: name, current, then the saved members except the token.
func (s ProfileSummary) Model() *core.Object {
	out := core.NewObject("name", s.Name, "current", s.Current)
	if s.Record != nil {
		for _, key := range s.Record.Keys() {
			if key != "token" {
				out.Set(key, s.Record.Get(key))
			}
		}
	}
	return out
}

var profileNamePattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// defaultProfile is the profile name used when nothing names one.
const defaultProfile = "default"

// CredentialsPath is where saved sessions live: BETTER_IAM_CREDENTIALS, else %APPDATA%\better-iam\credentials.json
// on Windows, else $XDG_CONFIG_HOME/better-iam/credentials.json or ~/.config/better-iam/credentials.json. Read only
// from the given environment, so an embedding program (and every test) decides whether a profile can be found at
// all; "" when the environment names no home or config directory.
func CredentialsPath(env map[string]string) string {
	if env["BETTER_IAM_CREDENTIALS"] != "" {
		resolved, err := filepath.Abs(env["BETTER_IAM_CREDENTIALS"])
		if err != nil {
			return env["BETTER_IAM_CREDENTIALS"]
		}
		return resolved
	}
	if runtime.GOOS == "windows" && env["APPDATA"] != "" {
		return filepath.Join(env["APPDATA"], "better-iam", "credentials.json")
	}
	home := env["HOME"]
	if home == "" {
		home = env["USERPROFILE"]
	}
	base := env["XDG_CONFIG_HOME"]
	if base == "" && home != "" {
		base = filepath.Join(home, ".config")
	}
	if base == "" {
		return ""
	}
	return filepath.Join(base, "better-iam", "credentials.json")
}

func assertProfileName(name string) (string, error) {
	if !profileNamePattern.MatchString(name) {
		return "", UsageError("Profile names use letters, digits, dot, dash, and underscore (at most 64)")
	}
	return name, nil
}

// ProfileStore reads and writes the saved-session file. Every write replaces the file atomically with mode 0600.
type ProfileStore struct {
	// Path is the file in use, or "" when the environment names no home or config directory.
	Path string
	env  map[string]string
}

// CreateProfileStore opens the saved-session file that login, logout, profiles, and token commands use, located
// from env (see CredentialsPath), so tools can list, save, or switch profiles the same way the CLI does.
func CreateProfileStore(env map[string]string) *ProfileStore {
	return &ProfileStore{Path: CredentialsPath(env), env: env}
}

type credentialsFile struct {
	current  string
	profiles *core.Object
}

func (s *ProfileStore) read() (credentialsFile, error) {
	empty := credentialsFile{profiles: core.NewObject()}
	if s.Path == "" {
		return empty, nil
	}
	raw, err := os.ReadFile(s.Path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return empty, nil
		}
		return empty, systemError(err)
	}
	invalid := NewCliError("INVALID_CREDENTIALS_FILE", s.Path+" is not a Better IAM credentials file",
		"Delete it or point BETTER_IAM_CREDENTIALS at another file, then run better-iam login.")
	parsed, err := core.ParseJSON(raw)
	if err != nil {
		return empty, invalid
	}
	object, ok := parsed.(*core.Object)
	if !ok || object == nil || !core.StrictEquals(object.Get("version"), 1.0) {
		return empty, invalid
	}
	profiles, ok := object.Get("profiles").(*core.Object)
	if !ok || profiles == nil {
		// An array is an object to JavaScript's typeof check, with no profiles in it.
		if _, isArray := object.Get("profiles").([]any); !isArray {
			return empty, invalid
		}
		profiles = core.NewObject()
	}
	file := credentialsFile{profiles: profiles}
	if current, ok := object.Get("current").(string); ok {
		file.current = current
	}
	return file, nil
}

func (s *ProfileStore) write(file credentialsFile) error {
	if s.Path == "" {
		return NewCliError("NO_CREDENTIALS_FILE", "No place to save sessions: HOME, APPDATA, and XDG_CONFIG_HOME are all unset",
			"Set BETTER_IAM_CREDENTIALS to a file path.")
	}
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o700); err != nil {
		return systemError(err)
	}
	random := make([]byte, 6)
	_, _ = rand.Read(random)
	temporary := s.Path + "." + hex.EncodeToString(random) + ".tmp"
	document := core.NewObject("version", 1.0)
	if file.current != "" {
		document.Set("current", file.current)
	}
	document.Set("profiles", file.profiles)
	body := stringifyIndented(jsonValue(document), "  ", "") + "\n"
	handle, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return systemError(err)
	}
	if _, err := handle.WriteString(body); err != nil {
		_ = handle.Close()
		_ = os.Remove(temporary)
		return systemError(err)
	}
	if err := handle.Close(); err != nil {
		_ = os.Remove(temporary)
		return systemError(err)
	}
	if err := os.Rename(temporary, s.Path); err != nil {
		_ = os.Remove(temporary)
		return systemError(err)
	}
	_ = os.Chmod(s.Path, 0o600)
	return nil
}

// CurrentName is --profile, else BETTER_IAM_PROFILE, else the file's current profile, else "default".
func (s *ProfileStore) CurrentName(explicit string) (string, error) {
	name := explicit
	if name == "" {
		name = s.env["BETTER_IAM_PROFILE"]
	}
	if name == "" {
		file, err := s.read()
		if err != nil {
			return "", err
		}
		name = file.current
	}
	if name == "" {
		name = defaultProfile
	}
	return assertProfileName(name)
}

func decodeProfile(value any) (*StoredProfile, error) {
	profile := &StoredProfile{}
	object, ok := value.(*core.Object)
	if !ok || object == nil {
		return profile, nil
	}
	profile.URL, _ = object.Get("url").(string)
	profile.Config, _ = object.Get("config").(string)
	profile.EnvConfig = object.Get("envConfig") == true
	profile.TenantID, _ = object.Get("tenantId").(string)
	profile.IdentityID, _ = object.Get("identityId").(string)
	profile.Email, _ = object.Get("email").(string)
	profile.Kind, _ = object.Get("kind").(string)
	profile.Token, _ = object.Get("token").(string)
	if expiresAt, ok := object.Get("expiresAt").(float64); ok {
		profile.ExpiresAt = &expiresAt
	}
	profile.SavedAt, _ = object.Get("savedAt").(float64)
	return profile, nil
}

// Get returns the profile saved under name, or nil.
func (s *ProfileStore) Get(name string) (*StoredProfile, error) {
	file, err := s.read()
	if err != nil {
		return nil, err
	}
	if !file.profiles.Has(name) {
		return nil, nil
	}
	return decodeProfile(file.profiles.Get(name))
}

// List returns every saved profile (without tokens), sorted by name, marking the current one.
func (s *ProfileStore) List(explicit string) ([]ProfileSummary, error) {
	file, err := s.read()
	if err != nil {
		return nil, err
	}
	current, err := s.CurrentName(explicit)
	if err != nil {
		return nil, err
	}
	names := file.profiles.Keys()
	sort.SliceStable(names, func(i, j int) bool { return localeCompare(names[i], names[j]) < 0 })
	out := make([]ProfileSummary, len(names))
	for index, name := range names {
		record, _ := file.profiles.Get(name).(*core.Object)
		out[index] = ProfileSummary{Name: name, Current: name == current, Record: record}
	}
	return out, nil
}

// profileRecord is the saved form of a profile, members in the order the TypeScript CLI writes them.
func profileRecord(profile *StoredProfile) *core.Object {
	record := core.NewObject()
	if profile.URL != "" {
		record.Set("url", profile.URL)
	}
	if profile.Config != "" {
		record.Set("config", profile.Config)
	}
	if profile.EnvConfig {
		record.Set("envConfig", true)
	}
	record.Set("token", profile.Token)
	if profile.TenantID != "" {
		record.Set("tenantId", profile.TenantID)
	}
	if profile.IdentityID != "" {
		record.Set("identityId", profile.IdentityID)
	}
	if profile.Email != "" {
		record.Set("email", profile.Email)
	}
	if profile.Kind != "" {
		record.Set("kind", profile.Kind)
	}
	if profile.ExpiresAt != nil {
		record.Set("expiresAt", *profile.ExpiresAt)
	}
	record.Set("savedAt", profile.SavedAt)
	return record
}

// Save stores a profile under name and, when makeCurrent, makes it the current one.
func (s *ProfileStore) Save(name string, profile *StoredProfile, makeCurrent bool) error {
	if _, err := assertProfileName(name); err != nil {
		return err
	}
	file, err := s.read()
	if err != nil {
		return err
	}
	file.profiles.Set(name, profileRecord(profile))
	if makeCurrent {
		file.current = name
	}
	return s.write(file)
}

// Remove forgets a profile; false when there was none.
func (s *ProfileStore) Remove(name string) (bool, error) {
	file, err := s.read()
	if err != nil {
		return false, err
	}
	if !file.profiles.Has(name) {
		return false, nil
	}
	file.profiles.Delete(name)
	if file.current == name {
		file.current = ""
	}
	return true, s.write(file)
}

// Use makes a saved profile the current one.
func (s *ProfileStore) Use(name string) error {
	file, err := s.read()
	if err != nil {
		return err
	}
	if _, err := assertProfileName(name); err != nil {
		return err
	}
	if !file.profiles.Has(name) {
		return NewCliError("NOT_FOUND", "No saved profile named "+name, "Run better-iam profiles to list them.")
	}
	file.current = name
	return s.write(file)
}
