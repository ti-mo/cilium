// Copyright 2020 Authors of Cilium
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

package certloader

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"

	"github.com/cilium/cilium/pkg/lock"
)

// Reloader is a set of TLS configuration files including custom CAs, and a
// certificate along with its private key (keypair) that can be reloaded
// dynamically via the Reload* functions.
type Reloader interface {
	// Ready returns true when the Reloader is ready to be used, false
	// otherwise.
	Ready() bool
	// KeypairConfigured returns true when the Reloader contains both a
	// certificate and its private key, false otherwise.
	KeypairConfigured() bool
	// CertificateAuthorityConfigured returns true when the Reloader has custom
	// CA configured, false otherwise.
	CertificateAuthorityConfigured() bool
	// KeypairAndCA returns both the configured keypair and CAs. This function
	// should only be called once the Reloader is ready, see Ready().
	KeypairAndCACertPool() (*tls.Certificate, *x509.CertPool)
	// Reload update the certificate authority and the keypair.
	Reload() (*tls.Certificate, *x509.CertPool, error)
	// ReloadKeypair update the keypair.
	ReloadKeypair() (*tls.Certificate, error)
	// ReloadCertificateAuthority update the certificate authority.
	ReloadCertificateAuthority() (*x509.CertPool, error)
}

// FileReloader is a Reloader implementation backed by local files.
type FileReloader struct {
	// NOTE: caFiles, certFile, and privkeyFile are constants for the
	// FileReloader's lifetime, thus accessing them doesn't require acquiring
	// the mutex.
	caFiles     []string
	certFile    string
	privkeyFile string
	// NOTE: caCertPool and keypair should only be accessed with mu acquired as
	// they may be updated concurrently.
	mu         lock.Mutex
	caCertPool *x509.CertPool
	keypair    *tls.Certificate
}

var (
	// ErrInvalidKeypair is returned when either the certificate or its
	// corresponding private key is missing.
	ErrInvalidKeypair = errors.New("certificate and private key are both required, but only one was provided")
)

// NewFileReloaderReady create and returns a FileReloader using the given file.
// The files are already loaded when this function returns, thus the returned
// FileReloader is readily usable.
func NewFileReloaderReady(caFiles []string, certFile, privkeyFile string) (*FileReloader, error) {
	r, err := NewFileReloader(caFiles, certFile, privkeyFile)
	if err != nil {
		return nil, err
	}

	// load the files for the first time.
	if _, _, err := r.Reload(); err != nil {
		return nil, err
	}

	return r, nil
}

// NewFileReloader create and returns a FileReloader using the given file. The
// files are not loaded when this function returns, and the caller is expected
// to call the Reload* functions until the returned FileReloader become ready.
func NewFileReloader(caFiles []string, certFile, privkeyFile string) (*FileReloader, error) {
	if certFile != "" && privkeyFile == "" {
		return nil, ErrInvalidKeypair
	}
	if certFile == "" && privkeyFile != "" {
		return nil, ErrInvalidKeypair
	}

	r := &FileReloader{
		caFiles:     caFiles,
		certFile:    certFile,
		privkeyFile: privkeyFile,
	}

	return r, nil
}

// Ready implements Reloader.
func (r *FileReloader) Ready() bool {
	keypair, caCertPool := r.KeypairAndCACertPool()
	if r.KeypairConfigured() && keypair == nil {
		return false
	}
	if r.CertificateAuthorityConfigured() && caCertPool == nil {
		return false
	}
	return true
}

// KeypairConfigured implements Reloader.
func (r *FileReloader) KeypairConfigured() bool {
	return r.certFile != "" && r.privkeyFile != ""
}

// CertificateAuthorityConfigured implements Reloader.
func (r *FileReloader) CertificateAuthorityConfigured() bool {
	return len(r.caFiles) > 0
}

// KeypairAndCA implements Reloader.
func (r *FileReloader) KeypairAndCACertPool() (*tls.Certificate, *x509.CertPool) {
	r.mu.Lock()
	keypair := r.keypair
	caCertPool := r.caCertPool
	r.mu.Unlock()
	return keypair, caCertPool
}

// Reload implements Reloader by updating the caCertPool reading the caFiles,
// and the keypair reading certFile and privkeyFile.
func (r *FileReloader) Reload() (keypair *tls.Certificate, caCertPool *x509.CertPool, err error) {
	if r.CertificateAuthorityConfigured() {
		caCertPool, err = r.readCertificateAuthority()
		if err != nil {
			return
		}
	}
	if r.KeypairConfigured() {
		keypair, err = r.readKeypair()
		if err != nil {
			return
		}
	}

	r.mu.Lock()
	if r.KeypairConfigured() {
		r.keypair = keypair
	}
	if r.CertificateAuthorityConfigured() {
		r.caCertPool = caCertPool
	}
	r.mu.Unlock()

	return
}

// ReloadKeypair implements Reloader by updating the keypair reading certFile
// and privkeyFile.
func (r *FileReloader) ReloadKeypair() (*tls.Certificate, error) {
	if !r.KeypairConfigured() {
		return nil, nil
	}

	keypair, err := r.readKeypair()
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	r.keypair = keypair
	r.mu.Unlock()
	return keypair, nil
}

// ReloadCertificateAuthority implements Reloader by updating the caCertPool
// reading the caFiles.
func (r *FileReloader) ReloadCertificateAuthority() (*x509.CertPool, error) {
	if !r.CertificateAuthorityConfigured() {
		return nil, nil
	}

	caCertPool, err := r.readCertificateAuthority()
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	r.caCertPool = caCertPool
	r.mu.Unlock()
	return caCertPool, nil
}

// readKeypair read the certificate and private key.
func (r *FileReloader) readKeypair() (*tls.Certificate, error) {
	keypair, err := tls.LoadX509KeyPair(r.certFile, r.privkeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load keypair: %s", err)
	}
	return &keypair, nil
}

// readCertificateAuthority read the CA files.
func (r *FileReloader) readCertificateAuthority() (*x509.CertPool, error) {
	caCertPool := x509.NewCertPool()
	for _, path := range r.caFiles {
		pem, err := ioutil.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to load cert %q: %s", path, err)
		}
		if ok := caCertPool.AppendCertsFromPEM(pem); !ok {
			return nil, fmt.Errorf("failed to load cert %q: must be PEM encoded", path)
		}
	}
	return caCertPool, nil
}
