package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"slices"
	"testing"
	"time"

	"github.com/opentelekomcloud/gophertelekomcloud/openstack/elb/v3/certificates"
)

func TestKeepCertPattern(t *testing.T) {
	t.Setenv(EnvKeepCertRegex, "")
	if got := keepCertPattern(); got != "dummy" {
		t.Fatalf("unset pattern: got %q, want dummy", got)
	}

	t.Setenv(EnvKeepCertRegex, "^prod-")
	pattern, err := regexp.Compile(keepCertPattern())
	if err != nil {
		t.Fatal(err)
	}
	if !pattern.MatchString("prod-certificate") || pattern.MatchString("test-certificate") {
		t.Fatal("pattern did not select only matching certificate names")
	}
}

func TestShouldDeleteOldCertificate(t *testing.T) {
	pattern := regexp.MustCompile("dummy")
	cases := []struct {
		name      string
		cert      *certificates.Certificate
		lookupErr error
		want      bool
	}{
		{name: "lookup failed", lookupErr: errors.New("unavailable")},
		{name: "missing certificate"},
		{name: "protected", cert: &certificates.Certificate{Name: "k8s-dummy"}},
		{name: "unprotected", cert: &certificates.Certificate{Name: "k8s-production"}, want: true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := shouldDeleteOldCertificate(testCase.cert, testCase.lookupErr, pattern); got != testCase.want {
				t.Fatalf("shouldDeleteOldCertificate() = %t, want %t", got, testCase.want)
			}
		})
	}
}

func TestListenerSlot(t *testing.T) {
	cases := []struct {
		value   string
		want    string
		wantErr bool
	}{
		{value: "", want: SlotDefault},
		{value: "default", want: SlotDefault},
		{value: "sni", want: SlotSNI},
		{value: "SNI", wantErr: true},
	}
	for _, testCase := range cases {
		annotations := map[string]string{}
		if testCase.value != "" {
			annotations[AnnotationListenerSlot] = testCase.value
		}
		got, err := listenerSlot(annotations)
		if (err != nil) != testCase.wantErr || got != testCase.want {
			t.Fatalf("listenerSlot(%q) = %q, %v; want %q, error %t", testCase.value, got, err, testCase.want, testCase.wantErr)
		}
	}
}

func TestSyncStateKeepsDefaultFormat(t *testing.T) {
	cert := []byte("certificate")
	legacy := fmt.Sprintf("%x-%s", sha256.Sum256(cert), "listener")
	if got := syncState(cert, "listener", SlotDefault); got != legacy {
		t.Fatalf("default slot state changed: got %q, want %q", got, legacy)
	}
	if got := syncState(cert, "listener", SlotSNI); got == legacy {
		t.Fatal("SNI state must differ from the default state, so switching slots re-syncs")
	}
}

func TestCertificateDomains(t *testing.T) {
	leaf := testCertificatePEM(t, "app.example.com", "app.example.com", "panel.example.com")
	cases := []struct {
		name    string
		pem     []byte
		want    []string
		wantErr bool
	}{
		{name: "leaf followed by its issuer", pem: append(slices.Clone(leaf), testCertificatePEM(t, "issuer", "issuer.example.com")...), want: []string{"app.example.com", "panel.example.com"}},
		{name: "no DNS SANs", pem: testCertificatePEM(t, "common-name-only"), wantErr: true},
		{name: "not PEM", pem: []byte("garbage"), wantErr: true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got, err := certificateDomains(testCase.pem)
			if (err != nil) != testCase.wantErr || !slices.Equal(got, testCase.want) {
				t.Fatalf("certificateDomains() = %v, %v; want %v, error %t", got, err, testCase.want, testCase.wantErr)
			}
		})
	}
}

func testCertificatePEM(t *testing.T, commonName string, dnsNames ...string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		DNSNames:     dnsNames,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestOwnedSNICertificate(t *testing.T) {
	entries := []certificates.Certificate{
		{ID: "manual", Name: "uploaded-by-hand"},
		{ID: "longer", Name: "k8s-app-tls-extra-1700000000"},
		{ID: "other-app", Name: "k8s-grafana-tls-1700000000"},
		{ID: "own-old", Name: "k8s-app-tls-1700000000"},
		{ID: "own-renamed", Name: "renamed-by-hand"},
	}
	cases := []struct {
		name       string
		entries    []certificates.Certificate
		recordedID string
		want       string
	}{
		{name: "recorded ID wins over the name", entries: entries, recordedID: "own-renamed", want: "own-renamed"},
		{name: "stale recorded ID falls back to the name", entries: entries, recordedID: "gone", want: "own-old"},
		{name: "no annotation falls back to the name", entries: entries, want: "own-old"},
		{name: "longer Secret name with the same prefix is not ours", entries: entries[:3]},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := ownedSNICertificate(testCase.entries, testCase.recordedID, "app-tls"); got != testCase.want {
				t.Fatalf("ownedSNICertificate() = %q, want %q", got, testCase.want)
			}
		})
	}
}

func TestSNIRefsForUpdate(t *testing.T) {
	entries := []certificates.Certificate{
		{ID: "a", Domain: "a.example.com"},
		{ID: "old", Domain: "app.example.com"},
		{ID: "manual", Domain: "other.example.com, APP.example.com"},
		{ID: "wildcard", Domain: "*.example.com"},
	}
	cases := []struct {
		name        string
		entries     []certificates.Certificate
		ownID       string
		want        []string
		wantUnbound []string
	}{
		{name: "rotation replaces own entry, unbinds same name, keeps others", entries: entries, ownID: "old", want: []string{"a", "wildcard", "new"}, wantUnbound: []string{"manual"}},
		{name: "first sync takes over a manual certificate", entries: entries[2:], want: []string{"wildcard", "new"}, wantUnbound: []string{"manual"}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got, unbound := sniRefsForUpdate(testCase.entries, testCase.ownID, "new", []string{"app.example.com"})
			if !slices.Equal(got, testCase.want) || !slices.Equal(unbound, testCase.wantUnbound) {
				t.Fatalf("sniRefsForUpdate() = %v, %v; want %v, %v", got, unbound, testCase.want, testCase.wantUnbound)
			}
		})
	}
}
