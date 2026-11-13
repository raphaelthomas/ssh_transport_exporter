// Package knownhosts checks host keys against known_hosts files like OpenSSH.
// It returns x/crypto's knownhosts errors and, like x/crypto, accepts a CA key
// as a plain host key if its @cert-authority line matches.
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

type hostKeyDB []line

// New reads known_hosts files and returns a host key callback that matches
// host patterns like OpenSSH.
func New(files ...string) (ssh.HostKeyCallback, error) {
	var db hostKeyDB
	for _, file := range files {
		lines, err := read(file)
		if err != nil {
			return nil, err
		}
		db = append(db, lines...)
	}
	return db.check, nil
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

// check verifies key for hostname like x/crypto's knownhosts callback, but
// only lines that match hostname apply, @revoked ones included. CertChecker's
// IsRevoked gets no host name, so check builds a CertChecker per call.
func (db hostKeyDB) check(hostname string, remote net.Addr, key ssh.PublicKey) error {
	name := strings.ToLower(knownhosts.Normalize(hostname))
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
	return checker.CheckHostKey(hostname, remote, key)
}

// checkPlain checks a plain host key like x/crypto: every matching line except
// @revoked ones, @cert-authority included, lists an accepted key.
func (db hostKeyDB) checkPlain(name string, key ssh.PublicKey) error {
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
func (db hostKeyDB) revoked(name string, key ssh.PublicKey) *line {
	blob := plainKeyBlob(key)
	for l := range db.matching(name) {
		if l.marker == markerRevoked && plainKeyBlob(l.known.Key) == blob {
			return l
		}
	}
	return nil
}

// matching yields the lines that apply to name.
func (db hostKeyDB) matching(name string) iter.Seq[*line] {
	return func(yield func(*line) bool) {
		for i := range db {
			if db[i].matches(name) && !yield(&db[i]) {
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
