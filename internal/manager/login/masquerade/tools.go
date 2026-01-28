package masquerade

import (
	"context"
	"proxylogin/internal/manager/tools"
)

func GetNewKey(ctx context.Context) (string, error) {
	for {
		key := tools.GenerateRandomString(keyLength)
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		if ok, err := masqueradeStorage.HasMasqueradedRecord(ctx, key); err == nil && !ok {
			return key, nil
		} else if err != nil {
			return "", err
		}
	}
}
