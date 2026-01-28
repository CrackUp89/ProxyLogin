package locking

import (
	"context"
	"proxylogin/internal/manager/rds"
	"proxylogin/internal/manager/tools"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func testSuccess(t *testing.T, once ReturnOnce[string]) {
	wg := &sync.WaitGroup{}
	counter := int32(0)
	results := make([]string, 0, 10)
	errors := make([]error, 0, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			r, err := once.Do(context.Background(), func(_ context.Context) (string, error) {
				time.Sleep(1 * time.Second)
				atomic.AddInt32(&counter, 1)
				return "success", nil
			})
			results = append(results, r)
			if err != nil {
				errors = append(errors, err)
			}
			wg.Done()
		}()
	}
	wg.Wait()
	assert.Equal(t, int32(1), atomic.LoadInt32(&counter))
	assert.Equal(t, len(results), 10)
	assert.Equal(t, len(errors), 0)
	assert.Equal(t, results[0], "success")
	assert.True(t, tools.AllInSlice(results, func(a string, b string) bool {
		return a == b
	}))
}

func testTimeout(t *testing.T, once ReturnOnce[string]) {
	wg := &sync.WaitGroup{}
	results := make([]string, 0, 10)
	errors := make([]error, 0, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			r, err := once.Do(context.Background(), func(_ context.Context) (string, error) {
				time.Sleep(3 * time.Second)
				return "should timeout", nil
			})
			if err != nil {
				errors = append(errors, err)
			} else {
				results = append(results, r)
			}
			wg.Done()
		}()
	}
	wg.Wait()
	assert.Equal(t, 0, len(results))
	assert.Equal(t, 10, len(errors))
}

func testPanic(t *testing.T, once ReturnOnce[string]) {
	wg := &sync.WaitGroup{}
	results := make([]string, 0, 10)
	errors := make([]error, 0, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			r, err := once.Do(context.Background(), func(_ context.Context) (string, error) {
				time.Sleep(3 * time.Second)
				panic("should panic")
			})
			if err != nil {
				errors = append(errors, err)
			} else {
				results = append(results, r)
			}
			wg.Done()
		}()
	}
	wg.Wait()
	assert.Equal(t, 0, len(results))
	assert.Equal(t, 10, len(errors))
	assert.Equal(t, errors[0].Error(), "should panic")
	assert.True(t, tools.AllInSlice(errors, func(a error, b error) bool {
		return a.Error() == b.Error()
	}))
}

func TestLocalReturnOnce_Do(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		once := getLocalReturnOnce[string]("test", 10*time.Second)
		testSuccess(t, once)
	})

	t.Run("timeout", func(t *testing.T) {
		once := getLocalReturnOnce[string]("test", 1*time.Second)
		testTimeout(t, once)
	})

	t.Run("panic", func(t *testing.T) {
		once := getLocalReturnOnce[string]("test", 10*time.Second)
		testPanic(t, once)
	})
}

func TestRedisReturnOnce_Do(t *testing.T) {
	viper.SetDefault("redis.url", "redis://localhost:6389/0?protocol=3")
	rds.LoadConfig()

	t.Run("success", func(t *testing.T) {
		once := getRedisReturnOnce[string]("test", 10*time.Second)
		testSuccess(t, once)
	})

	t.Run("timeout", func(t *testing.T) {
		once := getRedisReturnOnce[string]("test", 1*time.Second)
		testTimeout(t, once)
	})

	t.Run("panic", func(t *testing.T) {
		once := getRedisReturnOnce[string]("test", 10*time.Second)
		testPanic(t, once)
	})
}
