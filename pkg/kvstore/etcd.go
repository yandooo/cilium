// Copyright 2016-2018 Authors of Cilium
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

package kvstore

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/lock"

	client "github.com/coreos/etcd/clientv3"
	"github.com/coreos/etcd/clientv3/concurrency"
	clientyaml "github.com/coreos/etcd/clientv3/yaml"
	v3rpcErrors "github.com/coreos/etcd/etcdserver/api/v3rpc/rpctypes"
	"github.com/hashicorp/go-version"
	"github.com/sirupsen/logrus"
	ctx "golang.org/x/net/context"
)

const (
	// EtcdBackendName is the backend name fo etcd
	EtcdBackendName = "etcd"

	addrOption       = "etcd.address"
	EtcdOptionConfig = "etcd.config"
)

type etcdModule struct {
	opts   backendOptions
	config *client.Config
}

var (
	// etcdVersionMismatchFatal defines whether the agent should die
	// immediately if an etcd not matching the minimal version is
	// encountered.
	etcdVersionMismatchFatal = true

	// versionCheckTimeout is the time we wait trying to verify the version
	// of an etcd endpoint. The timeout can be encountered on network
	// connectivity problems.
	versionCheckTimeout = 30 * time.Second

	// statusCheckTimeout is the timeout when performing status checks with
	// all etcd endpoints
	statusCheckTimeout = 5 * time.Second

	// statusCheckInterval is the interval in which the status is checked
	statusCheckInterval = 5 * time.Second

	// initialConnectionTimeout  is the timeout for the initial connection to
	// the etcd server
	initialConnectionTimeout = 3 * time.Minute

	minRequiredVersion, _ = version.NewConstraint(">= 3.1.0")

	// etcdDummyAddress can be overwritten from test invokers using ldflags
	etcdDummyAddress = "http://127.0.0.1:4002"

	etcdInstance = &etcdModule{
		opts: backendOptions{
			addrOption: &backendOption{
				description: "Addresses of etcd cluster",
			},
			EtcdOptionConfig: &backendOption{
				description: "Path to etcd configuration file",
			},
		},
	}
)

func EtcdDummyAddress() string {
	return etcdDummyAddress
}

func (e *etcdModule) createInstance() backendModule {
	cpy := *etcdInstance
	return &cpy
}

func (e *etcdModule) getName() string {
	return EtcdBackendName
}

func (e *etcdModule) setConfigDummy() {
	e.config = &client.Config{}
	e.config.Endpoints = []string{etcdDummyAddress}
}

func (e *etcdModule) setConfig(opts map[string]string) error {
	return setOpts(opts, e.opts)
}

func (e *etcdModule) getConfig() map[string]string {
	return getOpts(e.opts)
}

func (e *etcdModule) newClient() (BackendOperations, error) {
	endpointsOpt, endpointsSet := e.opts[addrOption]
	configPathOpt, configSet := e.opts[EtcdOptionConfig]
	configPath := ""

	if e.config == nil {
		if !endpointsSet && !configSet {
			return nil, fmt.Errorf("invalid etcd configuration, %s or %s must be specified",
				EtcdOptionConfig, addrOption)
		}

		e.config = &client.Config{}

		if endpointsSet {
			e.config.Endpoints = []string{endpointsOpt.value}
		}

		if configSet {
			configPath = configPathOpt.value
		}
	}

	return newEtcdClient(e.config, configPath)
}

func init() {
	// register etcd module for use
	registerBackend(EtcdBackendName, etcdInstance)
}

type etcdClient struct {
	// firstSession is a channel that will be closed once the first session
	// is set up in the etcd Client.
	firstSession chan struct{}

	client               *client.Client
	controllers          *controller.Manager
	statusCheckerStarted sync.Once

	// protects session from concurrent access
	lock.RWMutex
	session *concurrency.Session

	// statusLock protects latestStatusSnapshot and latestErrorStatus for
	// read/write access
	statusLock lock.RWMutex

	// latestStatusSnapshot is a snapshot of the latest etcd cluster status
	latestStatusSnapshot string

	// latestErrorStatus is the latest error condition of the etcd connection
	latestErrorStatus error
}

type etcdMutex struct {
	mutex *concurrency.Mutex
}

func (e *etcdMutex) Unlock() error {
	return e.mutex.Unlock(ctx.Background())
}

// GetLeaseID returns the current lease ID.
func (e *etcdClient) GetLeaseID() client.LeaseID {
	e.RWMutex.RLock()
	l := e.session.Lease()
	e.RWMutex.RUnlock()
	return l
}

func (e *etcdClient) renewSession() error {
	<-e.firstSession
	<-e.session.Done()

	newSession, err := concurrency.NewSession(e.client, concurrency.WithTTL(int(LeaseTTL.Seconds())))
	if err != nil {
		return fmt.Errorf("Unable to renew etcd session: %s", err)
	}

	e.Lock()
	e.session = newSession
	e.Unlock()

	log.WithField(fieldSession, newSession).Debug("Renewing etcd session")

	go e.checkMinVersion()

	return nil
}

func newEtcdClient(config *client.Config, cfgPath string) (BackendOperations, error) {
	var (
		c   *client.Client
		err error
	)
	if cfgPath != "" {
		config, err = clientyaml.NewConfig(cfgPath)
		if err != nil {
			return nil, err
		}
	}
	if config != nil {
		// Set DialTimeout to 0, otherwise the creation of a new client will
		// block until DialTimeout is reached or a connection to the server
		// is made.
		config.DialTimeout = 0
		c, err = client.New(*config)
	} else {
		err = fmt.Errorf("empty configuration provided")
	}
	if err != nil {
		return nil, err
	}
	log.Info("Waiting for etcd client to be ready")

	var s concurrency.Session
	firstSession := make(chan struct{})
	sessionChan := make(chan *concurrency.Session)
	errorChan := make(chan error)

	// create session in parallel as this is a blocking operation
	go func() {
		session, err := concurrency.NewSession(c)
		errorChan <- err
		sessionChan <- session
		close(sessionChan)
		close(errorChan)
	}()

	ec := &etcdClient{
		client:               c,
		session:              &s,
		firstSession:         firstSession,
		controllers:          controller.NewManager(),
		latestStatusSnapshot: "No connection to etcd",
	}

	// wait for session to be created also in parallel
	go func() {
		var session concurrency.Session
		select {
		case err = <-errorChan:
			if err == nil {
				session = *<-sessionChan
			}
		case <-time.After(initialConnectionTimeout):
			err = fmt.Errorf("timed out while waiting for etcd session. Ensure that etcd is running on %s", config.Endpoints)
		}
		if err != nil {
			log.Fatal(err)
			return
		}

		log.Debugf("Session received")
		s = session
		if err != nil {
			c.Close()
			err = fmt.Errorf("unable to create default lease: %s", err)
			log.Fatal(err)
			return
		}
		close(ec.firstSession)
	}()

	ec.statusCheckerStarted.Do(func() {
		go ec.statusChecker()
	})

	go ec.checkMinVersion()

	ec.controllers.UpdateController("kvstore-etcd-session-renew",
		controller.ControllerParams{
			DoFunc: func() error {
				return ec.renewSession()
			},
			RunInterval: time.Duration(10) * time.Millisecond,
		},
	)

	return ec, nil
}

func getEPVersion(c client.Maintenance, etcdEP string, timeout time.Duration) (*version.Version, error) {
	ctxTimeout, cancel := ctx.WithTimeout(ctx.Background(), timeout)
	defer cancel()
	sr, err := c.Status(ctxTimeout, etcdEP)
	if err != nil {
		return nil, err
	}
	v, err := version.NewVersion(sr.Version)
	if err != nil {
		return nil, fmt.Errorf("error parsing server version %q: %s", sr.Version, err)
	}
	return v, nil
}

// checkMinVersion checks the minimal version running on etcd cluster. If the
// minimal version running doesn't meet cilium minimal requirements, a fatal
// log message is printed which terminates the agent. This function should be
// run whenever the etcd client is connected for the first time and whenever
// the session is renewed.
func (e *etcdClient) checkMinVersion() bool {
	eps := e.client.Endpoints()

	for _, ep := range eps {
		v, err := getEPVersion(e.client.Maintenance, ep, versionCheckTimeout)
		if err != nil {
			log.WithError(err).WithField(fieldEtcdEndpoint, ep).
				Warn("Unable to verify version of etcd endpoint")
			continue
		}

		if !minRequiredVersion.Check(v) {
			// FIXME: after we rework the refetching IDs for a connection lost
			// remove this Errorf and replace it with a warning
			if etcdVersionMismatchFatal {
				log.Fatalf("Minimal etcd version not met in %q, required: %s, found: %s",
					ep, minRequiredVersion.String(), v.String())
			}
			return false
		}

		log.WithFields(logrus.Fields{
			fieldEtcdEndpoint: ep,
			"version":         v,
		}).Debug("Successfully verified version of etcd endpoint")
	}

	if len(eps) == 0 {
		log.Warn("Minimal etcd version unknown: No etcd endpoints available")
	}

	return true
}

func (e *etcdClient) LockPath(path string) (kvLocker, error) {
	<-e.firstSession
	e.RLock()
	mu := concurrency.NewMutex(e.session, path)
	e.RUnlock()

	ctx, cancel := ctx.WithTimeout(ctx.Background(), 1*time.Minute)
	defer cancel()
	err := mu.Lock(ctx)
	if err != nil {
		return nil, err
	}

	return &etcdMutex{mutex: mu}, nil
}

func (e *etcdClient) DeletePrefix(path string) error {
	_, err := e.client.Delete(ctx.Background(), path, client.WithPrefix())
	return err
}

// Watch starts watching for changes in a prefix
func (e *etcdClient) Watch(w *Watcher) {
	localCache := watcherCache{}
	listSignalSent := false

	scopedLog := log.WithFields(logrus.Fields{
		fieldWatcher: w,
		fieldPrefix:  w.prefix,
	})

reList:
	for {
		res, err := e.client.Get(ctx.Background(), w.prefix, client.WithPrefix(),
			client.WithSerializable())
		if err != nil {
			scopedLog.WithError(err).Warn("Unable to list keys before starting watcher")
			continue
		}

		nextRev := res.Header.Revision + 1
		scopedLog.Debugf("List response from etcd len=%d: %+v", res.Count, res)

		if res.Count > 0 {
			for _, key := range res.Kvs {
				t := EventTypeCreate
				if localCache.Exists(key.Key) {
					t = EventTypeModify
				}

				localCache.MarkInUse(key.Key)
				scopedLog.Debugf("Emitting list result as %v event for %s=%v", t, key.Key, key.Value)

				w.Events <- KeyValueEvent{
					Key:   string(key.Key),
					Value: key.Value,
					Typ:   t,
				}
			}
		}

		// More keys to be read, call Get() again
		if res.More {
			continue
		}

		// Send out deletion events for all keys that were deleted
		// between our last known revision and the latest revision
		// received via Get
		localCache.RemoveDeleted(func(k string) {
			event := KeyValueEvent{
				Key: k,
				Typ: EventTypeDelete,
			}

			scopedLog.Debugf("Emitting EventTypeDelete event for %s", k)
			w.Events <- event
		})

		// Only send the list signal once
		if !listSignalSent {
			w.Events <- KeyValueEvent{Typ: EventTypeListDone}
			listSignalSent = true
		}

	recreateWatcher:
		scopedLog.WithField(fieldRev, nextRev).Debug("Starting to watch a prefix")
		etcdWatch := e.client.Watch(ctx.Background(), w.prefix,
			client.WithPrefix(), client.WithRev(nextRev))
		for {
			select {
			case <-w.stopWatch:
				close(w.Events)
				w.stopWait.Done()
				return

			case r, ok := <-etcdWatch:
				if !ok {
					time.Sleep(50 * time.Millisecond)
					goto recreateWatcher
				}

				scopedLog := scopedLog.WithField(fieldRev, r.Header.Revision)

				if err := r.Err(); err != nil {
					// We tried to watch on a compacted
					// revision that may no longer exist,
					// recreate the watcher and try to
					// watch on the next possible revision
					if err == v3rpcErrors.ErrCompacted {
						scopedLog.WithError(err).Debug("Tried watching on compacted revision")
					}

					// mark all local keys in state for
					// deletion unless the upcoming GET
					// marks them alive
					localCache.MarkAllForDeletion()

					goto reList
				}

				nextRev = r.Header.Revision + 1
				scopedLog.Debugf("Received event from etcd: %+v", r)

				for _, ev := range r.Events {
					event := KeyValueEvent{
						Key:   string(ev.Kv.Key),
						Value: ev.Kv.Value,
					}

					switch {
					case ev.Type == client.EventTypeDelete:
						event.Typ = EventTypeDelete
						localCache.RemoveKey(ev.Kv.Key)
					case ev.IsCreate():
						event.Typ = EventTypeCreate
						localCache.MarkInUse(ev.Kv.Key)
					default:
						event.Typ = EventTypeModify
						localCache.MarkInUse(ev.Kv.Key)
					}

					scopedLog.Debugf("Emitting %v event for %s=%v", event.Typ, event.Key, event.Value)

					w.Events <- event
				}
			}
		}
	}
}

func (e *etcdClient) determineEndpointStatus(endpointAddress string) (string, error) {
	ctxTimeout, cancel := ctx.WithTimeout(ctx.Background(), statusCheckTimeout)
	defer cancel()

	log.Debugf("Checking status to etcd endpoint %s", endpointAddress)

	status, err := e.client.Status(ctxTimeout, endpointAddress)
	if err != nil {
		return fmt.Sprintf("%s - %s", endpointAddress, err), err
	}

	str := fmt.Sprintf("%s - %s", endpointAddress, status.Version)
	if status.Header.MemberId == status.Leader {
		str += " (Leader)"
	}

	return str, nil
}

func (e *etcdClient) statusChecker() error {
	for {
		newStatus := []string{}
		ok := 0

		log.Debugf("Performing status check to etcd")

		endpoints := e.client.Endpoints()
		for _, ep := range endpoints {
			st, err := e.determineEndpointStatus(ep)
			if err == nil {
				ok++
			}

			newStatus = append(newStatus, st)
		}

		e.statusLock.Lock()
		e.latestStatusSnapshot = fmt.Sprintf("etcd: %d/%d connected: %s", ok, len(endpoints), strings.Join(newStatus, "; "))

		// Only mark the etcd health as unstable if no etcd endpoints can be reached
		if len(endpoints) > 0 && ok == 0 {
			e.latestErrorStatus = fmt.Errorf("Not able to connect to any etcd endpoints")
		} else {
			e.latestErrorStatus = nil
		}

		e.statusLock.Unlock()

		time.Sleep(statusCheckInterval)
	}
}

func (e *etcdClient) Status() (string, error) {
	e.statusLock.RLock()
	defer e.statusLock.RUnlock()

	return e.latestStatusSnapshot, e.latestErrorStatus
}

// Get returns value of key
func (e *etcdClient) Get(key string) ([]byte, error) {
	getR, err := e.client.Get(ctx.Background(), key)
	if err != nil {
		return nil, err
	}

	if getR.Count == 0 {
		return nil, nil
	}
	return getR.Kvs[0].Value, nil
}

// GetPrefix returns the first key which matches the prefix
func (e *etcdClient) GetPrefix(prefix string) ([]byte, error) {
	getR, err := e.client.Get(ctx.Background(), prefix, client.WithPrefix())
	if err != nil {
		return nil, err
	}

	if getR.Count == 0 {
		return nil, nil
	}
	return getR.Kvs[0].Value, nil
}

// Set sets value of key
func (e *etcdClient) Set(key string, value []byte) error {
	_, err := e.client.Put(ctx.Background(), key, string(value))
	return err
}

// Delete deletes a key
func (e *etcdClient) Delete(key string) error {
	_, err := e.client.Delete(ctx.Background(), key)
	return err
}

func (e *etcdClient) createOpPut(key string, value []byte, lease bool) *client.Op {
	if lease {
		op := client.OpPut(key, string(value), client.WithLease(e.GetLeaseID()))
		return &op
	}

	op := client.OpPut(key, string(value))
	return &op
}

// Update creates or updates a key
func (e *etcdClient) Update(key string, value []byte, lease bool) error {
	<-e.firstSession
	if lease {
		_, err := e.client.Put(ctx.Background(), key, string(value), client.WithLease(e.GetLeaseID()))
		return err
	}

	_, err := e.client.Put(ctx.Background(), key, string(value))
	return err
}

// CreateOnly creates a key with the value and will fail if the key already exists
func (e *etcdClient) CreateOnly(key string, value []byte, lease bool) error {
	req := e.createOpPut(key, value, lease)
	cond := client.Compare(client.Version(key), "=", 0)
	txnresp, err := e.client.Txn(ctx.TODO()).If(cond).Then(*req).Commit()
	if err != nil {
		return err
	}

	if txnresp.Succeeded == false {
		return fmt.Errorf("create was unsuccessful")
	}

	return nil
}

// CreateIfExists creates a key with the value only if key condKey exists
func (e *etcdClient) CreateIfExists(condKey, key string, value []byte, lease bool) error {
	req := e.createOpPut(key, value, lease)
	cond := client.Compare(client.Version(condKey), "!=", 0)
	txnresp, err := e.client.Txn(ctx.TODO()).If(cond).Then(*req).Commit()
	if err != nil {
		return err
	}

	if txnresp.Succeeded == false {
		return fmt.Errorf("create was unsuccessful")
	}

	return nil
}

// FIXME: When we rebase to etcd 3.3
//
// DeleteOnZeroCount deletes the key if no matching keys for prefix exist
//func (e *etcdClient) DeleteOnZeroCount(key, prefix string) error {
//	txnresp, err := e.client.Txn(ctx.TODO()).
//		If(client.Compare(client.Version(prefix).WithPrefix(), "=", 0)).
//		Then(client.OpDelete(key)).
//		Commit()
//	if err != nil {
//		return err
//	}
//
//	if txnresp.Succeeded == false {
//		return fmt.Errorf("delete was unsuccessful")
//	}
//
//	return nil
//}

// ListPrefix returns a map of matching keys
func (e *etcdClient) ListPrefix(prefix string) (KeyValuePairs, error) {
	getR, err := e.client.Get(ctx.Background(), prefix, client.WithPrefix())
	if err != nil {
		return nil, err
	}

	pairs := KeyValuePairs{}
	for i := int64(0); i < getR.Count; i++ {
		pairs[string(getR.Kvs[i].Key)] = getR.Kvs[i].Value

	}

	return pairs, nil
}

// Close closes the etcd session
func (e *etcdClient) Close() {
	<-e.firstSession
	if e.controllers != nil {
		e.controllers.RemoveAll()
	}
	e.RLock()
	defer e.RUnlock()
	e.session.Close()
	e.client.Close()
}

// GetCapabilities returns the capabilities of the backend
func (e *etcdClient) GetCapabilities() Capabilities {
	return Capabilities(CapabilityCreateIfExists)
}

// Encode encodes a binary slice into a character set that the backend supports
func (e *etcdClient) Encode(in []byte) string {
	return string(in)
}

// Decode decodes a key previously encoded back into the original binary slice
func (e *etcdClient) Decode(in string) ([]byte, error) {
	return []byte(in), nil
}

// ListAndWatch implements the BackendOperations.ListAndWatch using etcd
func (e *etcdClient) ListAndWatch(name, prefix string, chanSize int) *Watcher {
	w := newWatcher(name, prefix, chanSize)

	log.WithField(fieldWatcher, w).Debug("Starting watcher...")

	go e.Watch(w)

	return w
}
