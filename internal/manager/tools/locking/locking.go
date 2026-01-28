package locking

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"proxylogin/internal/manager/config"
	"proxylogin/internal/manager/rds"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

type ReturnOnceFunc[T any] = func(context.Context) (T, error)

type ReturnOnce[T any] interface {
	Do(context.Context, ReturnOnceFunc[T]) (T, error)
	Key() string
}

type ReturnOnceWrapper[T any] struct {
	ro ReturnOnce[T]
}

var roRegistry = new(sync.Map)

func (r *ReturnOnceWrapper[T]) Do(ctx context.Context, rof ReturnOnceFunc[T]) (T, error) {
	defer roRegistry.Delete(r.ro.Key())
	return r.ro.Do(ctx, rof)
}

func (r *ReturnOnceWrapper[T]) Key() string {
	return r.ro.Key()
}

type LocalReturnOnce[T any] struct {
	key    string
	ttl    time.Duration
	once   *sync.Once
	mutex  *sync.Mutex
	result T
	err    error
}

func (l *LocalReturnOnce[T]) Key() string {
	return l.key
}

func (l *LocalReturnOnce[T]) Do(ctx context.Context, f ReturnOnceFunc[T]) (T, error) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.once.Do(func() {
		resultChan := make(chan T, 1)
		errChan := make(chan error)

		timeoutCtx, cancel := context.WithTimeout(ctx, l.ttl)
		defer cancel()

		go func() {
			defer func() {
				recovered := recover()
				if recovered != nil {
					if recoveryErr, ok := recovered.(error); ok {
						errChan <- recoveryErr
					} else {
						errChan <- errors.New(fmt.Sprint(recovered))
					}
				}
			}()
			r, err := f(timeoutCtx)
			if err != nil {
				errChan <- err
			} else {
				resultChan <- r
			}
		}()

		select {
		case <-timeoutCtx.Done():
			l.err = timeoutCtx.Err()
			break
		case l.err = <-errChan:
			break
		case l.result = <-resultChan:
			break
		}

	})
	return l.result, l.err
}

func getLocalReturnOnce[T any](key string, ttl time.Duration) ReturnOnce[T] {
	r, _ := roRegistry.LoadOrStore(key,
		&LocalReturnOnce[T]{
			key:   key,
			ttl:   ttl,
			once:  &sync.Once{},
			mutex: &sync.Mutex{},
		})
	return &ReturnOnceWrapper[T]{
		ro: r.(ReturnOnce[T]),
	}
}

type RedisReturnOnce[T any] struct {
	key    string
	ttl    time.Duration
	once   *sync.Once
	mutex  *sync.Mutex
	result T
	err    error
}

func (r *RedisReturnOnce[T]) Key() string {
	return r.key
}

func getErrorKey(key string) string {
	return rds.BuildKey("returnOnce:", key+".error")
}

func getResultKey(key string) string {
	return rds.BuildKey("returnOnce:", key+".result")
}

func getLockKey(key string) string {
	return rds.BuildKey("returnOnce:", key+".lock")
}

func (r *RedisReturnOnce[T]) Do(ctx context.Context, f ReturnOnceFunc[T]) (T, error) {

	r.mutex.Lock()
	defer r.mutex.Unlock()

	r.once.Do(func() {
		lockKey := getLockKey(r.key)
		resultKey := getResultKey(r.key)
		errorKey := getErrorKey(r.key)

		client := rds.GetClient()

		ps := client.Subscribe(ctx, resultKey, errorKey)
		psResultChan := make(chan T, 1)
		psErrChan := make(chan error)

		defer func() {
			_ = ps.Unsubscribe(ctx)
		}()

		psRecover := func() {
			recovered := recover()
			if recovered != nil {
				psErrChan <- recovered.(error)
			}
		}

		go func() {
			defer psRecover()
			for {
				m, err := ps.ReceiveTimeout(ctx, r.ttl)
				if err != nil {
					psErrChan <- err
				}

				switch t := m.(type) {
				case *redis.Message:
					if t.Channel == resultKey {
						var r T
						err = json.Unmarshal([]byte(t.Payload), &r)
						if err == nil {
							psResultChan <- r
						} else {
							psErrChan <- err
						}
					} else {
						psErrChan <- errors.New(t.Payload)
					}
				}
			}
		}()

		errNotify := func(err error) {
			client.Publish(ctx, errorKey, err.Error())
		}

		var result T
		acquired, err := client.SetNX(ctx, lockKey, uuid.New().String(), r.ttl).Result()
		if err != nil {
			errNotify(err)
			r.err = err
			return
		}

		if acquired {
			timeoutCtx, cancel := context.WithTimeout(ctx, r.ttl)
			defer cancel()

			resultChan := make(chan T, 1)
			errChan := make(chan error)

			go func() {
				defer client.Del(context.Background(), lockKey)
				defer func() {
					recovered := recover()
					if recovered != nil {
						if recoveryErr, ok := recovered.(error); ok {
							errChan <- recoveryErr
						} else {
							errChan <- errors.New(fmt.Sprint(recovered))
						}
					}
				}()
				r, err := f(timeoutCtx)
				if err != nil {
					errChan <- err
				} else {
					resultChan <- r
				}
			}()

			select {
			case <-timeoutCtx.Done():
				err = timeoutCtx.Err()
				break
			case err = <-errChan:
				break
			case result = <-resultChan:
				break
			}

			if err != nil {
				errNotify(err)
			} else {
				var b []byte
				b, err = json.Marshal(result)
				if err != nil {
					errNotify(err)
				} else {
					_, err = client.Publish(ctx, resultKey, b).Result()
					if err != nil {
						errNotify(err)
					}
				}
			}

			r.result = result
			r.err = err
			return
		}

		select {
		case r.err = <-psErrChan:
			break
		case r.result = <-psResultChan:
			break
		}
	})

	return r.result, r.err
}

func getRedisReturnOnce[T any](key string, ttl time.Duration) ReturnOnce[T] {
	r, _ := roRegistry.LoadOrStore(key,
		&RedisReturnOnce[T]{
			key:   key,
			ttl:   ttl,
			once:  &sync.Once{},
			mutex: &sync.Mutex{},
		})
	return &ReturnOnceWrapper[T]{
		ro: r.(ReturnOnce[T]),
	}
}

func GetReturnOnce[T any](key string, ttl time.Duration) ReturnOnce[T] {
	switch config.GetStorageType() {
	case config.MemoryStorageType:
		return getLocalReturnOnce[T](key, ttl)
	case config.RedisStorageType:
		return getRedisReturnOnce[T](key, ttl)
	}
	panic("unreachable")
}
