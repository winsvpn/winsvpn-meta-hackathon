package masque

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

func selfSigned(t *testing.T) tls.Certificate {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "127.0.0.1"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

type seen struct {
	r   *http.Request
	req *ProxyRequest
	err error
}

func TestParseProxyRequestRealHTTP3Server(t *testing.T) {
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	hostport := pc.LocalAddr().String()
	template := uritemplate.MustNew("https://" + hostport + "/masque?h={target_host}&p={target_port}")
	ch := make(chan seen, 4)
	srv := &http3.Server{
		TLSConfig:       &tls.Config{Certificates: []tls.Certificate{selfSigned(t)}, NextProtos: []string{http3.NextProtoH3}},
		EnableDatagrams: true,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			pr, err := ParseProxyRequest(r, template)
			ch <- seen{r, pr, err}
			if err != nil {
				w.WriteHeader(400)
				return
			}
			w.WriteHeader(200)
		}),
	}
	go srv.Serve(pc)
	defer srv.Close()

	tr := &Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{http3.NextProtoH3}},
		QUICConfig: &quic.Config{EnableDatagrams: true, InitialPacketSize: 1350}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := NewRequest(ctx, template, "example.org:443")
	if err != nil {
		t.Fatal(err)
	}
	conn, rsp, err := tr.Dial(req)
	s := <-ch
	if s.r.URL.Scheme != "" || s.r.URL.Host != "" {
		t.Fatalf("server request URL %v carries scheme or host; the path-and-query shape this test pins has changed", s.r.URL)
	}
	if s.err != nil || s.req == nil || s.req.Target != "example.org:443" || s.req.Host != hostport {
		t.Fatalf("ParseProxyRequest on a real HTTP/3 server request: %+v, %v", s.req, s.err)
	}
	if err != nil {
		t.Fatalf("dial: %v (rsp=%v)", err, rsp)
	}
	conn.Close()
}
