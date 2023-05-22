// Copyright 2023 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tsa

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
	tsaverification "github.com/sigstore/timestamp-authority/pkg/verification"
)

// Verifier represents a mechanism to get and verify Rekor entries for the given Git commit.
type Verifier interface {
	Verify(ctx context.Context, tsBytes, signedTimestamp []byte) error
}

// Client implements a basic rekor implementation for writing and verifying Rekor data.
type Client struct {
	// TSACertificate verifies that the TSR uses the TSACertificate as expected. Optional if the TSR contains the TSA certificate
	TSACertificate *x509.Certificate
	// Intermediates verifies the TSR's certificate. Optional, used for chain building
	Intermediates []*x509.Certificate
	// Roots is the set of trusted root certificates that verifies the TSR's certificate
	Roots []*x509.Certificate
}

func New(certChainPath string) (Verifier, error) {
	co := &Client{}
	_, err := os.Stat(certChainPath)
	if err != nil {
		return nil, fmt.Errorf("unable to open timestamp certificate chain file: %w", err)
	}
	// TODO: Add support for TUF certificates.
	pemBytes, err := os.ReadFile(filepath.Clean(certChainPath))
	if err != nil {
		return nil, fmt.Errorf("error reading certification chain path file: %w", err)
	}

	leaves, intermediates, roots, err := splitPEMCertificateChain(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("error splitting certificates: %w", err)
	}
	if len(leaves) > 1 {
		return nil, fmt.Errorf("certificate chain must contain at most one TSA certificate")
	}
	if len(leaves) == 1 {
		co.TSACertificate = leaves[0]
	}
	co.Intermediates = intermediates
	co.Roots = roots
	return co, nil
}

func (c *Client) Verify(ctx context.Context, tsBytes, signedTimestamp []byte) error {
	fmt.Fprintln(os.Stderr, "~~~~~~~~~~~~~~~~~~~~ verifying the TSA Here ~~~~~~~~~~~~~~")

	_, err := tsaverification.VerifyTimestampResponse(signedTimestamp, bytes.NewReader(tsBytes),
		tsaverification.VerifyOpts{
			TSACertificate: c.TSACertificate,
			Intermediates:  c.Intermediates,
			Roots:          c.Roots,
		})
	return err
}

// splitPEMCertificateChain returns a list of leaf (non-CA) certificates, a certificate pool for
// intermediate CA certificates, and a certificate pool for root CA certificates
func splitPEMCertificateChain(pem []byte) (leaves, intermediates, roots []*x509.Certificate, err error) {
	certs, err := cryptoutils.UnmarshalCertificatesFromPEM(pem)
	if err != nil {
		return nil, nil, nil, err
	}

	for _, cert := range certs {
		if !cert.IsCA {
			leaves = append(leaves, cert)
		} else {
			// root certificates are self-signed
			if bytes.Equal(cert.RawSubject, cert.RawIssuer) {
				roots = append(roots, cert)
			} else {
				intermediates = append(intermediates, cert)
			}
		}
	}

	return leaves, intermediates, roots, nil
}
