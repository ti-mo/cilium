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
	"fmt"
	"path/filepath"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

// Watcher is a set of TLS configuration files including CA files, and a
// certificate along with its private key. The files are watched for change and
// reloaded automatically.
type Watcher struct {
	*FileReloader
	log       logrus.FieldLogger
	fswatcher *fsnotify.Watcher
	stop      chan struct{}
}

// NewWatcher returns a Watcher that watch over the given file
// paths. The given files are expected to already exists when this function is
// called. On success, the returned Watcher is ready to use.
func NewWatcher(log logrus.FieldLogger, caFiles []string, certFile, privkeyFile string) (*Watcher, error) {
	r, err := NewFileReloaderReady(caFiles, certFile, privkeyFile)
	if err != nil {
		return nil, err
	}
	// An error here would be unexpected as we were able to create a
	// FileReloader having read the files, so their directory should exist and
	// be "watchable".
	fswatcher, err := newFsWatcher(caFiles, certFile, privkeyFile)
	if err != nil {
		return nil, err
	}
	w := &Watcher{
		FileReloader: r,
		log:          log,
		fswatcher:    fswatcher,
		stop:         make(chan struct{}),
	}

	w.Watch()
	return w, nil
}

// EventualWatcher returns a channel where exactly one Watcher will be sent
// once the given files are ready and loaded. This can be useful when the file
// paths are well-known, but the files themselves don't exist yet.
func EventualWatcher(log logrus.FieldLogger, caFiles []string, certFile, privkeyFile string) (<-chan *Watcher, error) {
	r, err := NewFileReloader(caFiles, certFile, privkeyFile)
	if err != nil {
		return nil, err
	}
	fswatcher, err := newFsWatcher(caFiles, certFile, privkeyFile)
	if err != nil {
		return nil, err
	}
	w := &Watcher{
		FileReloader: r,
		log:          log,
		fswatcher:    fswatcher,
		stop:         make(chan struct{}),
	}

	res := make(chan *Watcher)
	go func(res chan<- *Watcher) {
		defer close(res)
		// Attempt a reload without having received any fs notification in case
		// all the files are already there. Note that the keypair and CA are
		// reloaded separately as a "partial update" is still useful: If the
		// FileReloader is "half-ready" (e.g. has loaded the keypair but failed
		// to load the CA), we only need a successfully handled CA related fs
		// notify event to become Ready (in other words, we don't need to
		// receive a fs event for the keypair in that case to become ready).
		_, keypairErr := w.ReloadKeypair()
		_, caErr := w.ReloadCertificateAuthority()
		ready := w.Watch()
		if keypairErr == nil && caErr == nil {
			log.Debug("ready")
			res <- w
			return
		}
		log.Debug("waiting on fsnotify update to be ready")
		select {
		case <-ready:
			log.Debug("ready")
			res <- w
		case <-w.stop:
		}
	}(res)

	return res, nil
}

// Watch initialize the files watcher and update goroutine. It returns a ready
// channel that will be close once an update made the underlying FileReloader
// ready.
func (w *Watcher) Watch() chan struct{} {
	// build maps for the CA files and keypair files to help detecting what has
	// changed in order to reload only the appropriate certificates.
	keypairMap := make(map[string]struct{})
	caMap := make(map[string]struct{})
	if w.FileReloader.certFile != "" {
		keypairMap[w.FileReloader.certFile] = struct{}{}
	}
	if w.FileReloader.privkeyFile != "" {
		keypairMap[w.FileReloader.privkeyFile] = struct{}{}
	}
	for _, path := range w.FileReloader.caFiles {
		caMap[path] = struct{}{}
	}

	// prepare the ready channel to be returned. We will close it exactly once.
	var once sync.Once
	ready := make(chan struct{})
	go func() {
		defer w.fswatcher.Close()
		for {
			select {
			case event := <-w.fswatcher.Events:
				log := w.log.WithFields(logrus.Fields{
					logfields.Path: event.Name,
					"operation":    event.Op,
				})
				log.Debug("Received fsnotify event")
				switch event.Op {
				case fsnotify.Create, fsnotify.Write, fsnotify.Chmod, fsnotify.Remove, fsnotify.Rename:
					updated := false
					if _, ok := keypairMap[event.Name]; ok {
						keypair, err := w.ReloadKeypair()
						if err != nil {
							log.WithError(err).Warn("keypair update failed")
						} else {
							updated = true
							id := keypairId(keypair)
							log.WithField("keypair-id", id).Info("keypair updated")
						}
					} else if _, ok := caMap[event.Name]; ok {
						if _, err := w.ReloadCertificateAuthority(); err != nil {
							log.WithError(err).Warn("certificate authority update failed")
						} else {
							updated = true
							log.Info("certificate authority updated")
						}
					} else {
						log.Debug("unknown file, ignoring.")
					}
					if updated && w.Ready() {
						once.Do(func() {
							close(ready)
						})
					}
				default:
					log.Warn("unknown fsnotify event, ignoring.")
				}
			case err := <-w.fswatcher.Errors:
				w.log.WithError(err).Warn("fsnotify watcher error")
			case <-w.stop:
				w.log.Info("Stopping fsnotify watcher")
				return
			}
		}
	}()

	return ready
}

// Stop watching the files.
func (w *Watcher) Stop() {
	close(w.stop)
}

// newFsWatcher returns a fsnotify.Watcher watching over the given file's
// directories. Note that we're watching on the directories containing the
// files we're interested in, not the file themselves. We're doing this because
// fsnotify can't watch over non-existing file, and by watching the directory
// we can catch file creation.
func newFsWatcher(caFiles []string, certFile, privkeyFile string) (*fsnotify.Watcher, error) {
	fswatcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	if certFile != "" {
		dir := filepath.Dir(certFile)
		if err := fswatcher.Add(dir); err != nil {
			fswatcher.Close()
			return nil, fmt.Errorf("Failed to add %q to fsnotify watcher: %s", dir, err)
		}
	}
	if privkeyFile != "" {
		dir := filepath.Dir(privkeyFile)
		if err := fswatcher.Add(dir); err != nil {
			fswatcher.Close()
			return nil, fmt.Errorf("Failed to add %q to fsnotify watcher: %s", dir, err)
		}
	}
	for _, path := range caFiles {
		dir := filepath.Dir(path)
		if err := fswatcher.Add(dir); err != nil {
			fswatcher.Close()
			return nil, fmt.Errorf("Failed to add %q to fsnotify watcher: %s", dir, err)
		}
	}
	return fswatcher, nil
}
