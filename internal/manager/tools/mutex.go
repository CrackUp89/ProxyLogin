package tools

import (
	"sync"
)

var mutexMap sync.Map

func GetNamedMutex(name string) *sync.Mutex {
	mutex, ok := mutexMap.Load(name)
	if !ok {
		newMutex := &sync.Mutex{}
		mutex, _ = mutexMap.LoadOrStore(name, newMutex)
	}
	return mutex.(*sync.Mutex)
}

type NamedMutexManager struct {
	mutexMap sync.Map
}

func (r *NamedMutexManager) GetNamedMutex(name string) *sync.Mutex {
	mutex, ok := r.mutexMap.Load(name)
	if !ok {
		newMutex := &sync.Mutex{}
		mutex, _ = r.mutexMap.LoadOrStore(name, newMutex)
	}
	return mutex.(*sync.Mutex)
}
