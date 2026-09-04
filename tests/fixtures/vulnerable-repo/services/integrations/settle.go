package integrations

import (
	"crypto/rsa"
	"crypto/tls"
	"net/http"
)

// Settlement client — talks to the bank over TLS.
func newClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // trusts any cert
		},
	}
}

func weakKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(nil, 1024) // 1024-bit RSA
}
