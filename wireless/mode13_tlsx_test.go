package wireless

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	tls "github.com/cB-Sigma/tlsx"
)

// brainpoolPKI is a brainpoolP256r1 CA with a gateway and a meter
// certificate on brainpoolP256r1 (OMS Vol 2 annex F: brainpool curves).
func brainpoolPKI(t *testing.T) (gw, meter tls.Certificate, pool *x509.CertPool) {
	t.Helper()
	caKey, err := tls.GenerateBrainpoolKey(tls.BrainpoolP256r1, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "OMS brainpool CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	caDER, err := tls.CreateCertificate(rand.Reader, caTpl, caTpl, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := tls.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leaf := func(cn string, usage x509.ExtKeyUsage, serial int64) tls.Certificate {
		k, err := tls.GenerateBrainpoolKey(tls.BrainpoolP256r1, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn}, DNSNames: []string{cn},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		der, err := tls.CreateCertificate(rand.Reader, tpl, ca, k.Public(), caKey)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
	}
	pool = x509.NewCertPool()
	pool.AddCert(ca)
	return leaf("gateway", x509.ExtKeyUsageServerAuth, 2), leaf("ABC-12345678", x509.ExtKeyUsageClientAuth, 3), pool
}

// Covers: SIG-SEC-676, SIG-SEC-690
// The gateway's mode 13 TLS server with an OMS meter that uses a
// brainpool certificate and curve, a CBC suite with encrypt-then-MAC, a
// 512-byte max_fragment_length, and resumes by session ID.
func TestMode13TLSXFeatures(t *testing.T) {
	gw, meter, pool := brainpoolPKI(t)
	srvCfg := ServerConfig(gw, pool)
	cliCfg := &tls.Config{Certificates: []tls.Certificate{meter}, RootCAs: pool, ServerName: "gateway",
		MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
		CipherSuites:       []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256},
		CurvePreferences:   []tls.CurveID{tls.BrainpoolP256r1},
		ClientSessionCache: tls.NewLRUClientSessionCache(2),
		Ext:                tls.ConfigExt{EncryptThenMAC: true, MaxFragmentLength: 1, ClientSessionIDs: true}}
	cliCfg.SessionTicketsDisabled = true // meters resume by session ID (annex F F.3.1)
	dial := func() tls.ConnectionState {
		t.Helper()
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		go func() {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s := tls.Server(c, srvCfg)
			defer s.Close()
			_, _ = io.Copy(s, s)
		}()
		c, err := tls.Dial("tcp", ln.Addr().String(), cliCfg)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		msg := make([]byte, 3000)
		if _, err := c.Write(msg); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(c, msg); err != nil {
			t.Fatal(err)
		}
		return c.ConnectionState()
	}
	cs := dial()
	if cs.CipherSuite != tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 || !cs.Ext.EncryptThenMAC || cs.CurveID != tls.BrainpoolP256r1 ||
		cs.Ext.MaxFragmentLength != 512 || cs.DidResume {
		t.Fatalf("suite %s etm %v curve %v mfl %d resumed %v", tls.CipherSuiteName(cs.CipherSuite), cs.Ext.EncryptThenMAC,
			cs.CurveID, cs.Ext.MaxFragmentLength, cs.DidResume)
	}
	if cs2 := dial(); !cs2.DidResume {
		t.Fatal("no resumption by session ID")
	}
	// CBC without encrypt-then-MAC: accepted for meters installed before
	// 2025 (BSI TR-03116-3 6.4.2), refused when requireEncryptThenMAC is set.
	noEtM := cliCfg.Clone()
	noEtM.Ext.EncryptThenMAC = false
	noEtM.ClientSessionCache = nil
	handshake := func(srv *tls.Config) (tls.ConnectionState, error) {
		a, b := net.Pipe()
		go func() { s := tls.Server(b, srv); _ = s.Handshake(); s.Close() }()
		c := tls.Client(a, noEtM)
		defer c.Close()
		err := c.Handshake()
		return c.ConnectionState(), err
	}
	if cs, err := handshake(srvCfg); err != nil || cs.Ext.EncryptThenMAC || cs.CipherSuite != tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 {
		t.Fatalf("legacy CBC meter: %v", err)
	}
	strict := srvCfg.Clone()
	strict.Ext.RequireEncryptThenMAC = true
	if _, err := handshake(strict); err == nil {
		t.Fatal("CBC without encrypt-then-MAC accepted in strict mode")
	}
}

// Covers: SIG-SEC-682
// Annex F Table F.2 curves and the F.D.3 suites are all accepted.
func TestMode13AnnexFCurvesAndSuites(t *testing.T) {
	gw, meter, pool := brainpoolPKI(t)
	srvCfg := ServerConfig(gw, pool)
	suites := []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384}
	// Every curve once and every suite once (the curve and the suite are
	// independent choices).
	for i, curve := range []tls.CurveID{tls.BrainpoolP256r1, tls.CurveP256, tls.BrainpoolP384r1, tls.CurveP384, tls.BrainpoolP512r1} {
		for _, suite := range suites[i%4 : i%4+1] {
			cli := &tls.Config{Certificates: []tls.Certificate{meter}, RootCAs: pool, ServerName: "gateway",
				MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{suite}, CurvePreferences: []tls.CurveID{curve},
				Ext: tls.ConfigExt{EncryptThenMAC: true}}
			a, b := net.Pipe()
			errc := make(chan error, 1)
			go func() { s := tls.Server(b, srvCfg); errc <- s.Handshake(); s.Close() }()
			c := tls.Client(a, cli)
			err := c.Handshake()
			cs := c.ConnectionState()
			c.Close()
			if err != nil || <-errc != nil || cs.CurveID != curve || cs.CipherSuite != suite {
				t.Fatalf("curve %v suite %s: %v", curve, tls.CipherSuiteName(suite), err)
			}
		}
	}
}

// Covers: SIG-SEC-688
// BSI TR-03116-3 6.3, Tables 4 and 17: LMN certificates on a Table 4
// curve (brainpoolP256r1/P384r1/P512r1, P-256, P-384) with ECDSA keys and
// at most 7 years of validity, for the gateway (settings refused) and the
// meter (handshake refused).
func TestMode13CertificateProfile(t *testing.T) {
	gw, meter, pool := brainpoolPKI(t)
	if err := CheckLMNCertificate(gw.Certificate[0]); err != nil {
		t.Fatalf("brainpool gateway certificate: %v", err)
	}
	now := time.Now()
	mk := func(key crypto.Signer, years int) []byte {
		tpl := &x509.Certificate{SerialNumber: big.NewInt(77), Subject: pkix.Name{CommonName: "x"},
			NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(years, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature}
		der, err := tls.CreateCertificate(rand.Reader, tpl, tpl, key.Public(), key)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	p521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for name, der := range map[string][]byte{"P-521": mk(p521, 1), "RSA": mk(rsaKey, 1), "8 years": mk(p256, 8)} {
		if err := CheckLMNCertificate(der); err == nil {
			t.Errorf("%s certificate accepted", name)
		}
	}
	if err := CheckLMNCertificate(mk(p256, 7)); err != nil {
		t.Errorf("P-256, 7 years: %v", err)
	}
	// A meter certificate outside the profile is refused in the handshake.
	bad := tls.Certificate{Certificate: [][]byte{mk(p521, 1)}, PrivateKey: p521}
	badPool := pool.Clone()
	c, _ := x509.ParseCertificate(bad.Certificate[0])
	badPool.AddCert(c)
	srv := ServerConfig(gw, badPool)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	errc := make(chan error, 1)
	go func() {
		b, err := ln.Accept()
		if err != nil {
			errc <- err
			return
		}
		s := tls.Server(b, srv)
		errc <- s.Handshake()
		s.Close()
	}()
	a, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cl := tls.Client(a, &tls.Config{Certificates: []tls.Certificate{bad}, RootCAs: pool, ServerName: "gateway", MaxVersion: tls.VersionTLS12})
	_ = cl.Handshake()
	cl.Close()
	if err := <-errc; err == nil || !strings.Contains(err.Error(), "TR-03116-3") {
		t.Fatalf("P-521 meter certificate: %v", err)
	}
	_ = meter
}

// Covers: SIG-SEC-689
// BSI TR-03116-3 6.1: a resumed session counts from its full handshake
// (ConnectionState.Ext.SessionCreated); renegotiation is not possible.
// SigmaM2M's adapter tests the configurable lifetime itself.
func TestMode13SessionResumption(t *testing.T) {
	// A resumed session starts its clock at the session's full handshake.
	gw, meter, pool := brainpoolPKI(t)
	srv := ServerConfig(gw, pool)
	cli := &tls.Config{Certificates: []tls.Certificate{meter}, RootCAs: pool, ServerName: "gateway", MaxVersion: tls.VersionTLS12,
		ClientSessionCache: tls.NewLRUClientSessionCache(2), Ext: tls.ConfigExt{ClientSessionIDs: true}, SessionTicketsDisabled: true,
		Renegotiation: tls.RenegotiateFreelyAsClient}
	var created time.Time
	for i := 0; i < 2; i++ {
		a, b := net.Pipe()
		st := make(chan tls.ConnectionState, 1)
		go func() {
			s := tls.Server(b, srv)
			_ = s.Handshake()
			st <- s.ConnectionState()
			_, _ = io.Copy(io.Discard, s)
		}()
		c := tls.Client(a, cli)
		if err := c.Handshake(); err != nil {
			t.Fatal(err)
		}
		ss := <-st
		if i == 1 {
			if !ss.DidResume || ss.Ext.SessionCreated.IsZero() || ss.Ext.SessionCreated.After(created.Add(time.Second)) {
				t.Fatalf("resumed %v created %v", ss.DidResume, ss.Ext.SessionCreated)
			}
			// No renegotiation (6.1): the gateway answers no_renegotiation.
			if err := c.Renegotiate(); err == nil {
				t.Fatal("renegotiation accepted")
			}
		}
		created = time.Now()
		c.Close()
	}
}
