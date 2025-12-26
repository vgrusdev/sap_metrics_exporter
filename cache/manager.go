package cache

import (
	"sync"
	"time"
)

type Manager struct {
	mu         sync.RWMutex
	instances  []InstanceInfo
	lastUpdate time.Time
	ttl        time.Duration
}

func NewManager(ttl time.Duration) *Manager {
	return &Manager{
		instances:  make([]InstanceInfo, 0),
		ttl:        ttl,
		lastUpdate: time.Time{},
	}
}

func (m *Manager) GetInstances() []InstanceInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.isStale() {
		return nil
	}

	return m.instances
}

func (m *Manager) SetInstances(instances []InstanceInfo) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.instances = instances
	m.lastUpdate = time.Now()
}

func (m *Manager) GetInstance(instanceNr string) *InstanceInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.isStale() {
		return nil
	}

	for i := range m.instances {
		if m.instances[i].InstanceNr == instanceNr {
			return &m.instances[i]
		}
	}

	return nil
}

func (m *Manager) UpdateInstance(instanceNr string, updater func(*InstanceInfo)) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i := range m.instances {
		if m.instances[i].InstanceNr == instanceNr {
			updater(&m.instances[i])
			return true
		}
	}

	return false
}

func (m *Manager) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.instances = make([]InstanceInfo, 0)
	m.lastUpdate = time.Time{}
}

func (m *Manager) IsStale() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.isStale()
}

func (m *Manager) isStale() bool {
	return time.Since(m.lastUpdate) > m.ttl || m.lastUpdate.IsZero()
}

func (m *Manager) GetStats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return map[string]interface{}{
		"instance_count": len(m.instances),
		"last_update":    m.lastUpdate,
		"is_stale":       m.isStale(),
		"ttl":            m.ttl.String(),
	}
}
