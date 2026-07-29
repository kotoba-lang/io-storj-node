// Command verify_minted reads an identity minted by storj.node.mint and asks
// storj.io/common whether it is a Storj identity.
//
// This is the check the rest of the repo's vectors cannot make. Everywhere
// else the reference implementation produces bytes and the .cljc asserts it
// reads them the same way; here the .cljc produces the bytes and the
// reference implementation is asked to accept them. A parser agreeing with
// its own writer proves nothing, and reading a certificate correctly is not
// evidence that one can be written.
//
//	go run verify_minted.go -in minted.edn
package main

import (
	"crypto/x509"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"regexp"

	"storj.io/common/identity"
	"storj.io/common/peertls"
	"storj.io/common/storj"
)

func mustField(src, name string) string {
	m := regexp.MustCompile(`:` + name + `\s+"([^"]*)"`).FindStringSubmatch(src)
	if m == nil {
		panic("missing field: " + name)
	}
	return m[1]
}

func mustNum(src, name string) string {
	m := regexp.MustCompile(`:` + name + `\s+(\d+)`).FindStringSubmatch(src)
	if m == nil {
		panic("missing numeric field: " + name)
	}
	return m[1]
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

var failed bool

func check(what string, ok bool) {
	if ok {
		fmt.Printf("ok   %s\n", what)
		return
	}
	fmt.Printf("FAIL %s\n", what)
	failed = true
}

func main() {
	in := flag.String("in", "minted.edn", "identity produced by storj.node.mint")
	flag.Parse()

	raw, err := os.ReadFile(*in)
	if err != nil {
		panic(err)
	}
	src := string(raw)

	// 1. the certificates parse at all — Go's X.509 parser is strict about
	//    lengths, tag classes and the shape of every extension
	caCert, err := x509.ParseCertificate(mustHex(mustField(src, "ca-der")))
	if err != nil {
		fmt.Printf("FAIL the CA certificate does not parse: %v\n", err)
		os.Exit(1)
	}
	leafCert, err := x509.ParseCertificate(mustHex(mustField(src, "leaf-der")))
	if err != nil {
		fmt.Printf("FAIL the leaf certificate does not parse: %v\n", err)
		os.Exit(1)
	}
	check("both certificates parse", true)

	// 2. the signatures verify, including the CA's over itself
	check("the CA signed itself",
		caCert.CheckSignature(caCert.SignatureAlgorithm,
			caCert.RawTBSCertificate, caCert.Signature) == nil)
	check("the CA signed the leaf",
		caCert.CheckSignature(leafCert.SignatureAlgorithm,
			leafCert.RawTBSCertificate, leafCert.Signature) == nil)

	// 3. Storj's own chain verification accepts it
	check("peertls.VerifyPeerCertChains accepts the chain",
		peertls.VerifyPeerCertChains(nil,
			[][]*x509.Certificate{{leafCert, caCert}}) == nil)

	// 4. and it names the node this library said it named
	id, err := identity.NodeIDFromCert(caCert)
	if err != nil {
		fmt.Printf("FAIL NodeIDFromCert: %v\n", err)
		os.Exit(1)
	}
	check("the node id matches", hex.EncodeToString(id.Bytes()) == mustField(src, "node-id"))

	d, err := id.Difficulty()
	if err != nil {
		fmt.Printf("FAIL Difficulty: %v\n", err)
		os.Exit(1)
	}
	check("the difficulty matches", fmt.Sprint(d) == mustNum(src, "difficulty"))

	v, err := storj.IDVersionFromCert(caCert)
	if err != nil {
		fmt.Printf("FAIL IDVersionFromCert: %v\n", err)
		os.Exit(1)
	}
	check("the identity version reads back", fmt.Sprint(v.Number) == mustNum(src, "version"))

	// 5. the structural details that are easy to get almost right
	check("the CA is a CA with a path-length-free basic constraint",
		caCert.IsCA && caCert.BasicConstraintsValid)
	check("the leaf is not a CA", !leafCert.IsCA && leafCert.BasicConstraintsValid)
	check("the CA's key usage is certSign alone",
		caCert.KeyUsage == x509.KeyUsageCertSign)
	check("the leaf's key usage is digitalSignature and keyEncipherment",
		leafCert.KeyUsage == x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment)
	check("the leaf is usable for both ends of a TLS connection",
		len(leafCert.ExtKeyUsage) == 2 &&
			leafCert.ExtKeyUsage[0] == x509.ExtKeyUsageServerAuth &&
			leafCert.ExtKeyUsage[1] == x509.ExtKeyUsageClientAuth)
	check("the subject is O=Storj on both",
		len(caCert.Subject.Organization) == 1 && caCert.Subject.Organization[0] == "Storj" &&
			len(leafCert.Subject.Organization) == 1 && leafCert.Subject.Organization[0] == "Storj")
	check("the CA carries a subjectKeyIdentifier and the leaf does not",
		len(caCert.SubjectKeyId) == 20 && len(leafCert.SubjectKeyId) == 0)
	check("neither carries an authorityKeyIdentifier",
		len(caCert.AuthorityKeyId) == 0 && len(leafCert.AuthorityKeyId) == 0)
	check("validity is Go's zero time",
		caCert.NotBefore.IsZero() && caCert.NotAfter.IsZero() &&
			leafCert.NotBefore.IsZero() && leafCert.NotAfter.IsZero())
	check("the serial numbers are 128-bit and different",
		caCert.SerialNumber.BitLen() > 112 &&
			caCert.SerialNumber.Cmp(leafCert.SerialNumber) != 0)

	// 6. and it works as an identity, not merely as a pair of certificates
	peer, err := identity.PeerIdentityFromChain([]*x509.Certificate{leafCert, caCert})
	if err != nil {
		fmt.Printf("FAIL PeerIdentityFromChain: %v\n", err)
		os.Exit(1)
	}
	check("PeerIdentityFromChain agrees about the id", peer.ID == id)

	if failed {
		os.Exit(1)
	}
}
