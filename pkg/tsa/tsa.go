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
	"context"
	"crypto/x509"

	"github.com/sigstore/rekor/pkg/generated/models"
)

// Verifier represents a mechanism to get and verify a TSA signature for the given Git commit.
type Verifier interface {
	Verify(ctx context.Context, commitSHA string, cert *x509.Certificate) (*models.LogEntryAnon, error)
}
