package masquerade

import (
	"context"
	"proxylogin/internal/manager/tools"
)

func (m *Masquerade) GetNewKey(ctx context.Context) (string, error) {
	for {
		key, err := tools.GenerateRandomString(m.cfg.KeyLength)
		if err != nil {
			return "", err
		}
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		if ok, err := m.storage.HasMasqueradedRecord(ctx, key); err == nil && !ok {
			return key, nil
		} else if err != nil {
			return "", err
		}
	}
}
