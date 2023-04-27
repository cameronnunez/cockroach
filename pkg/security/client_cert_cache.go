// Copyright 2023 The Cockroach Authors.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package security

import (
	"github.com/cockroachdb/cockroach/pkg/security/username"
	"github.com/cockroachdb/cockroach/pkg/settings"
	"github.com/cockroachdb/cockroach/pkg/settings/cluster"
	"github.com/cockroachdb/cockroach/pkg/util/cache"
	"github.com/cockroachdb/cockroach/pkg/util/mon"
	"github.com/cockroachdb/cockroach/pkg/util/syncutil"
	"time"
)

// ClientCertExpirationCacheCapacity is the cluster setting that controls the
// maximum number of client cert expirations in the cache.
var ClientCertExpirationCacheCapacity = settings.RegisterIntSetting(
	settings.TenantWritable,
	"server.client_cert_expiration_cache.capacity",
	"the maximum number of client cert expirations stored",
	1000,
).WithPublic()

// ClientCertExpirationCache is an in-memory FIFO cache that stores the minimum
// expiration time of client certs seen (per user).
type ClientCertExpirationCache struct {
	st *cluster.Settings

	mu struct {
		syncutil.RWMutex
		store *cache.UnorderedCache
	}

	mon *mon.BytesMonitor
}

func NewClientCertExpirationCache(st *cluster.Settings) *ClientCertExpirationCache {
	cacheConfig := cache.Config{
		Policy: cache.CacheFIFO,
		ShouldEvict: func(size int, _, _ interface{}) bool {
			return int64(size) > ClientCertExpirationCacheCapacity.Get(&st.SV)
		},
	}
	c := &ClientCertExpirationCache{st: st}
	c.mu.store = cache.NewUnorderedCache(cacheConfig)
	return c
}

// Get retrieves the cert expiration for the given username, if it exists.
func (c *ClientCertExpirationCache) Get(key username.SQLUsername) time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	value, ok := c.mu.store.Get(key)
	if !ok {
		return time.Time{}
	}
	return value.(time.Time)
}

// Upsert invalidates the cert expiration for the given user.
// The provided expiration is then inserted into the cache.
func (c *ClientCertExpirationCache) Upsert(key username.SQLUsername, value time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.mu.store.Del(key)
	c.mu.store.Add(key, value)
}

// Len returns the number of cert expirations in the cache.
func (c *ClientCertExpirationCache) Len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.mu.store.Len()
}
