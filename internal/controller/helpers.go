package controller

import (
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/fastly/go-fastly/fastly"
)

const (
	// LabelAppName for discovery.
	LabelAppName = "fastly.amazee.io/service-name"
	// LabelAppType for discovery.
	LabelAppType = "fastly.amazee.io/type"
	// LabelAppManaged for discovery.
	LabelAppManaged = "fastly.amazee.io/managed-by"
)

type fastlyAPI struct {
	Token                    string
	PlatformTLSConfiguration string
	ServiceID                string
	SecretName               string
}

// check if conditions contains a condition
func containsDomain(domains []*fastly.Domain, domainName string) bool {
	for _, domain := range domains {
		if domain.Name == domainName {
			return true
		}
	}
	return false
}

// check if a slice contains a string
func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

// remove string from a slice
func removeString(slice []string, s string) (result []string) {
	for _, item := range slice {
		if item == s {
			continue
		}
		result = append(result, item)
	}
	return
}

// check if the returned keys from fastly have the publickeysha1 we are looking for
func containsPrivateKey(privateKeys []*fastly.PrivateKey, publickeysha1 string) (bool, string) {
	for _, key := range privateKeys {
		if key.PublicKeySHA1 == publickeysha1 {
			return true, key.ID
		}
	}
	return false, ""
}

// decodecert helper function
func decodeCertificatePem(certInput []byte) tls.Certificate {
	var cert tls.Certificate
	certPEMBlock := certInput
	var certDERBlock *pem.Block
	for {
		certDERBlock, certPEMBlock = pem.Decode(certPEMBlock)
		if certDERBlock == nil {
			break
		}
		if certDERBlock.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, certDERBlock.Bytes)
		}
	}
	return cert
}

// certificates in platformtls are only identifiable via their publickeysha1
// we can get that sha1 with the following
func decodePrivateKeyToPublicKeySHA1(keyBytes []byte) (string, error) {
	var err error
	privPem, _ := pem.Decode(keyBytes)
	if privPem.Type != "RSA PRIVATE KEY" {
		return "", fmt.Errorf("unable to parse RSA privatekey")
	}
	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKCS1PrivateKey(privPem.Bytes); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(privPem.Bytes); err != nil {
			return "", fmt.Errorf("unable to parse RSA privatekey")
		}
	}
	rsaPrivateKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("unable to parse RSA privatekey")
	}
	pubASN1, err := x509.MarshalPKIXPublicKey(&rsaPrivateKey.PublicKey)
	if err != nil {
		return "", fmt.Errorf("unable to marshal publickey")
	}
	return fmt.Sprintf("%x", sha1.Sum(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	}))), nil
}

// split certificate into intermediate and certificate
func getCertsFromChain(certificate []byte) ([]byte, []byte, error) {
	var intermediateCert, mainCert []byte
	certChain := decodeCertificatePem(certificate)
	for _, cert := range certChain.Certificate {
		x509Cert, err := x509.ParseCertificate(cert)
		if err != nil {
			return mainCert, intermediateCert, err
		}
		b := pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert,
		}
		certPEM := pem.EncodeToMemory(&b)
		if x509Cert.IsCA {
			intermediateCert = certPEM
		} else {
			mainCert = certPEM
		}
	}
	return mainCert, intermediateCert, nil
}

func truncateString(str string, num int) string {
	bnoden := str
	if len(str) > num {
		if num > 3 {
			num -= 3
		}
		bnoden = str[0:num]
	}
	return bnoden
}
