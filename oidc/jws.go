package oidc

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"unicode/utf8"

	// Register the SHA-2 hashes the supported algorithms name.
	_ "crypto/sha256"
	_ "crypto/sha512"
)

// MaxTokenBytes bounds the compact serialization Verify will look at. Real ID
// tokens are 1–3 KiB; the cap stops an attacker-supplied header from costing
// megabytes of base64 and JSON work before any signature is checked.
const MaxTokenBytes = 16 << 10

// maxJSONDepth bounds nesting in the header, claims and fetched documents.
const maxJSONDepth = 32

// algorithm describes one JWS "alg" this package can verify (RFC 7518 §3).
type algorithm struct {
	kty  string      // required JWK key type: "RSA" or "EC"
	hash crypto.Hash // digest the signature covers
	pss  bool        // RSASSA-PSS rather than PKCS #1 v1.5
	crv  string      // required curve for EC ("P-256", ...)
	size int         // EC: byte length of r and of s
}

// supportedAlgorithms is the complete set of algorithms a Verifier can be
// configured with. "none" and the HMAC family (HS256/384/512) are absent on
// purpose: an OIDC verifier holds only the issuer's public keys, and accepting
// HS* is the classic confusion where the public key is used as an HMAC secret.
var supportedAlgorithms = map[string]algorithm{
	"RS256": {kty: "RSA", hash: crypto.SHA256},
	"RS384": {kty: "RSA", hash: crypto.SHA384},
	"RS512": {kty: "RSA", hash: crypto.SHA512},
	"PS256": {kty: "RSA", hash: crypto.SHA256, pss: true},
	"PS384": {kty: "RSA", hash: crypto.SHA384, pss: true},
	"PS512": {kty: "RSA", hash: crypto.SHA512, pss: true},
	"ES256": {kty: "EC", hash: crypto.SHA256, crv: "P-256", size: 32},
	"ES384": {kty: "EC", hash: crypto.SHA384, crv: "P-384", size: 48},
	"ES512": {kty: "EC", hash: crypto.SHA512, crv: "P-521", size: 66},
}

// Header is the protected JOSE header of a verified token.
type Header struct {
	Algorithm string // alg
	KeyID     string // kid
	Type      string // typ, if present
}

// compactJWS is a parsed, not yet verified, compact JWS.
type compactJWS struct {
	header       Header
	signingInput string // ASCII(BASE64URL(header) || '.' || BASE64URL(payload))
	payload      []byte // decoded claims JSON
	signature    []byte
}

// parseCompact splits and decodes a compact JWS strictly: exactly three
// non-empty segments, canonical unpadded base64url in each, a UTF-8 JSON
// object header with a string alg and kid and no "crit", and a UTF-8 JSON
// object payload. It checks nothing cryptographic. Every failure is
// ErrMalformed.
func parseCompact(raw string) (*compactJWS, error) {
	if len(raw) > MaxTokenBytes {
		return nil, fmt.Errorf("%w: token exceeds %d bytes", ErrMalformed, MaxTokenBytes)
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: want 3 segments, got %d", ErrMalformed, len(parts))
	}
	segs := make([][]byte, 3)
	for i, p := range parts {
		b, err := decodeSegment(p)
		if err != nil {
			return nil, fmt.Errorf("%w: segment %d: %w", ErrMalformed, i, err)
		}
		segs[i] = b
	}
	h, err := parseHeader(segs[0])
	if err != nil {
		return nil, err
	}
	if err := checkJSONObject(segs[1]); err != nil {
		return nil, fmt.Errorf("%w: claims: %w", ErrMalformed, err)
	}
	return &compactJWS{
		header:       h,
		signingInput: parts[0] + "." + parts[1],
		payload:      segs[1],
		signature:    segs[2],
	}, nil
}

var errNonCanonical = errors.New("not canonical unpadded base64url")

// decodeSegment decodes one segment as canonical unpadded base64url
// (RFC 7515 §2): only the URL-safe alphabet, no padding, no whitespace, and
// zero trailing bits. encoding/base64 alone silently skips CR and LF even in
// Strict mode, so the alphabet is checked first; Strict then rejects non-zero
// padding bits. Together they make the encoding unique, so a token has exactly
// one serialization and the signing input is exactly what was signed.
func decodeSegment(s string) ([]byte, error) {
	if s == "" {
		return nil, errors.New("empty")
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !isBase64URLChar(c) {
			return nil, errNonCanonical
		}
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, errNonCanonical
	}
	return b, nil
}

func isBase64URLChar(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') || c == '-' || c == '_'
}

// parseHeader decodes the protected header. alg and kid are required strings.
// "crit" is rejected outright: this verifier implements no JWS extensions, and
// RFC 7515 §4.1.11 requires rejecting a token whose critical extensions are not
// understood. jku, jwk, x5u and x5c are ignored — keys come only from the
// configured issuer's key set, never from the token.
func parseHeader(b []byte) (Header, error) {
	if err := checkJSONObject(b); err != nil {
		return Header{}, fmt.Errorf("%w: header: %w", ErrMalformed, err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return Header{}, fmt.Errorf("%w: header: %w", ErrMalformed, err)
	}
	if _, ok := raw["crit"]; ok {
		return Header{}, fmt.Errorf("%w: header: crit is not supported", ErrMalformed)
	}
	var h Header
	var err error
	if h.Algorithm, err = headerString(raw, "alg", true); err != nil {
		return Header{}, err
	}
	if h.KeyID, err = headerString(raw, "kid", true); err != nil {
		return Header{}, err
	}
	if h.Type, err = headerString(raw, "typ", false); err != nil {
		return Header{}, err
	}
	return h, nil
}

func headerString(raw map[string]json.RawMessage, name string, required bool) (string, error) {
	v, ok := raw[name]
	if !ok {
		if required {
			return "", fmt.Errorf("%w: header: %s missing", ErrMalformed, name)
		}
		return "", nil
	}
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		return "", fmt.Errorf("%w: header: %s is not a string", ErrMalformed, name)
	}
	if required && s == "" {
		return "", fmt.Errorf("%w: header: %s is empty", ErrMalformed, name)
	}
	return s, nil
}

// checkJSONObject accepts exactly one JSON object in valid UTF-8, with no
// duplicate member names at any depth, nesting at most maxJSONDepth, and
// nothing after it. encoding/json alone lets the last duplicate win and
// replaces invalid UTF-8 with U+FFFD; both let two parsers disagree about what
// a signed document says, so both are refused.
func checkJSONObject(b []byte) error {
	if !utf8.Valid(b) {
		return errors.New("invalid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return errors.New("not a JSON object")
	}
	if err := walkObject(dec, 1); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data after JSON object")
	}
	return nil
}

func walkObject(dec *json.Decoder, depth int) error {
	seen := make(map[string]struct{})
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := tok.(string)
		if !ok {
			return errors.New("invalid object key")
		}
		if _, dup := seen[key]; dup {
			return fmt.Errorf("duplicate member %q", key)
		}
		seen[key] = struct{}{}
		if err := walkValue(dec, depth); err != nil {
			return err
		}
	}
	_, err := dec.Token() // '}'
	return err
}

func walkValue(dec *json.Decoder, depth int) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	if depth >= maxJSONDepth {
		return errors.New("JSON nested too deeply")
	}
	if d == '{' {
		return walkObject(dec, depth+1)
	}
	for dec.More() { // '['
		if err := walkValue(dec, depth+1); err != nil {
			return err
		}
	}
	_, err = dec.Token() // ']'
	return err
}

// verifySignature checks sig over signingInput with key under alg. The caller
// has already established that alg is allowed and that key is compatible.
func verifySignature(alg algorithm, key crypto.PublicKey, signingInput string, sig []byte) error {
	h := alg.hash.New()
	h.Write([]byte(signingInput))
	digest := h.Sum(nil)

	switch pub := key.(type) {
	case *rsa.PublicKey:
		if alg.pss {
			opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: alg.hash}
			if err := rsa.VerifyPSS(pub, alg.hash, digest, sig, opts); err != nil {
				return ErrSignature
			}
			return nil
		}
		if err := rsa.VerifyPKCS1v15(pub, alg.hash, digest, sig); err != nil {
			return ErrSignature
		}
		return nil
	case *ecdsa.PublicKey:
		// JWS carries R || S as fixed-width big-endian integers (RFC 7518
		// §3.4), not ASN.1 DER. Any other length is rejected, never
		// reinterpreted.
		if len(sig) != 2*alg.size {
			return ErrSignature
		}
		r := new(big.Int).SetBytes(sig[:alg.size])
		s := new(big.Int).SetBytes(sig[alg.size:])
		if !ecdsa.Verify(pub, digest, r, s) {
			return ErrSignature
		}
		return nil
	default:
		return ErrAlgorithm
	}
}
