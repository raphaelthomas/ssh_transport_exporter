// Package knownhosts looks up known_hosts lines and checks host keys against
// them like OpenSSH. It returns x/crypto's knownhosts errors and, like x/crypto,
// accepts a CA key as a plain host key if its @cert-authority line matches.
package knownhosts

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // G505: known_hosts hashes host names with HMAC-SHA1.
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"iter"
	"net"
	"os"
	"slices"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/raphaelthomas/ssh_transport_exporter/internal/match"
)

const (
	markerCert    = "cert-authority"
	markerRevoked = "revoked"
)

// line is a valid known_hosts line. A hashed line has salt and hash instead of
// patterns.
type line struct {
	marker     string
	patterns   []string
	salt, hash []byte
	known      knownhosts.KnownKey
}

// DB is a parsed set of known_hosts files.
type DB struct {
	lines []line
}

// Line is a known_hosts line. CertAuthority marks a @cert-authority line,
// Revoked one whose key a @revoked line for the same host revokes.
type Line struct {
	knownhosts.KnownKey
	CertAuthority bool
	Revoked       bool
}

// Load reads known_hosts files.
func Load(files ...string) (*DB, error) {
	db := &DB{}
	for _, file := range files {
		lines, err := read(file)
		if err != nil {
			return nil, err
		}
		db.lines = append(db.lines, lines...)
	}
	return db, nil
}

// Lines returns the lines that match addr, host:port, @revoked ones aside, in
// file order.
func (db *DB) Lines(addr string) []Line {
	matching := slices.Collect(db.matching(lookupName(addr)))
	revoked := make(map[string]bool)
	for _, l := range matching {
		if l.marker == markerRevoked {
			revoked[plainKeyBlob(l.known.Key)] = true
		}
	}
	var lines []Line
	for _, l := range matching {
		if l.marker != markerRevoked {
			lines = append(lines, Line{KnownKey: l.known, CertAuthority: l.marker == markerCert, Revoked: revoked[plainKeyBlob(l.known.Key)]})
		}
	}
	return lines
}

// lookupName is OpenSSH's name for addr, host:port: host on port 22, else
// [host]:port.
func lookupName(addr string) string {
	return strings.ToLower(knownhosts.Normalize(addr))
}

// read parses file, skipping invalid lines like OpenSSH. Like x/crypto, it
// fails if file has invalid lines and no valid one.
func read(file string) ([]line, error) {
	//nolint:gosec // G304: reading the operator-supplied known_hosts path is the point.
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var lines []line
	var firstErr error
	for i, raw := range bytes.Split(data, []byte("\n")) {
		raw = bytes.TrimSpace(raw)
		if len(raw) == 0 || raw[0] == '#' {
			continue
		}
		l, err := parseLine(raw)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("knownhosts: %s: no valid entries, line %d: %w", file, i+1, err)
			}
			continue
		}
		l.known.Filename, l.known.Line = file, i+1
		lines = append(lines, l)
	}
	if len(lines) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return lines, nil
}

func parseLine(raw []byte) (line, error) {
	marker, hosts, key, _, _, err := ssh.ParseKnownHosts(raw)
	switch {
	case errors.Is(err, io.EOF):
		return line{}, errors.New("truncated line")
	case err != nil:
		return line{}, err
	case marker != "" && marker != markerCert && marker != markerRevoked:
		return line{}, fmt.Errorf("invalid marker %q", "@"+marker)
	}
	l := line{marker: marker, known: knownhosts.KnownKey{Key: key}}
	// Like OpenSSH, a host field starting with '|' is a single hashed name.
	field := strings.Join(hosts, ",")
	if field[0] == '|' {
		l.salt, l.hash, err = decodeHash(field)
		return l, err
	}
	l.patterns = strings.Split(strings.ToLower(field), ",")
	return l, nil
}

// decodeHash decodes a hashed host name, |1|salt|hash.
func decodeHash(field string) (salt, hash []byte, err error) {
	parts := strings.Split(field, "|")
	if len(parts) != 4 || parts[1] != "1" {
		return nil, nil, fmt.Errorf("invalid hashed host %q", field)
	}
	if salt, err = base64.StdEncoding.DecodeString(parts[2]); err != nil {
		return nil, nil, err
	}
	if hash, err = base64.StdEncoding.DecodeString(parts[3]); err != nil {
		return nil, nil, err
	}
	return salt, hash, nil
}

// matches reports whether l applies to name, OpenSSH's lookup name: host on
// port 22, else [host]:port.
func (l *line) matches(name string) bool {
	if l.patterns == nil {
		mac := hmac.New(sha1.New, l.salt)
		mac.Write([]byte(name))
		return hmac.Equal(mac.Sum(nil), l.hash)
	}
	matched := false
	for _, p := range l.patterns {
		negated := strings.HasPrefix(p, "!")
		if !match.Pattern(name, strings.TrimPrefix(p, "!")) {
			continue
		}
		if negated {
			return false
		}
		matched = true
	}
	return matched
}

// Check verifies key for addr, host:port, like x/crypto's knownhosts callback,
// but only lines that match addr apply, @revoked ones included. CertChecker's
// IsRevoked gets no host name, so Check builds a CertChecker per call.
func (db *DB) Check(addr string, key ssh.PublicKey) error {
	name := lookupName(addr)
	checker := ssh.CertChecker{
		IsHostAuthority: func(auth ssh.PublicKey, _ string) bool {
			for l := range db.matching(name) {
				if l.marker == markerCert && keyEq(l.known.Key, auth) {
					return true
				}
			}
			return false
		},
		IsRevoked: func(cert *ssh.Certificate) bool {
			return db.revoked(name, cert) != nil || db.revoked(name, cert.SignatureKey) != nil
		},
		HostKeyFallback: func(_ string, _ net.Addr, plain ssh.PublicKey) error {
			return db.checkPlain(name, plain)
		},
	}
	return checker.CheckHostKey(addr, nil, key)
}

// checkPlain checks a plain host key like x/crypto: every matching line except
// @revoked ones, @cert-authority included, lists an accepted key.
func (db *DB) checkPlain(name string, key ssh.PublicKey) error {
	if l := db.revoked(name, key); l != nil {
		return &knownhosts.RevokedError{Revoked: l.known}
	}
	keyErr := &knownhosts.KeyError{}
	for l := range db.matching(name) {
		if l.marker == markerRevoked {
			continue
		}
		keyErr.Want = append(keyErr.Want, l.known)
		if keyEq(l.known.Key, key) {
			return nil
		}
	}
	return keyErr
}

// revoked returns the @revoked line for name that revokes key, or nil. Like
// x/crypto, a certificate stands for the key it certifies.
func (db *DB) revoked(name string, key ssh.PublicKey) *line {
	blob := plainKeyBlob(key)
	for l := range db.matching(name) {
		if l.marker == markerRevoked && plainKeyBlob(l.known.Key) == blob {
			return l
		}
	}
	return nil
}

// matching yields the lines that apply to name; a nil DB has none.
func (db *DB) matching(name string) iter.Seq[*line] {
	return func(yield func(*line) bool) {
		if db == nil {
			return
		}
		for i := range db.lines {
			if db.lines[i].matches(name) && !yield(&db.lines[i]) {
				return
			}
		}
	}
}

func keyEq(a, b ssh.PublicKey) bool {
	return bytes.Equal(a.Marshal(), b.Marshal())
}

func plainKeyBlob(key ssh.PublicKey) string {
	if cert, ok := key.(*ssh.Certificate); ok {
		key = cert.Key
	}
	return string(key.Marshal())
}
