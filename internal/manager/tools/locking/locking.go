package locking

import (
	"proxylogin/internal/manager/redisclient"
	"proxylogin/internal/manager/storage"
)

// Provider hands out locks backed by the configured storage.
type Provider struct {
	storageType storage.Type
	client      *redisclient.ClientWrapper
	localLocks  localLocks
}

func NewProvider(storageType storage.Type, redisCfg redisclient.Config) *Provider {
	p := &Provider{storageType: storageType}
	if storageType == storage.RedisType {
		p.client = redisclient.GetDefaultClient(redisCfg)
	}
	return p
}
