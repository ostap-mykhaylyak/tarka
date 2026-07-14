package xfr

import (
	"sort"
	"time"
)

// monitorInterval paces the master-side lag checks.
const monitorInterval = 60 * time.Second

// LagInfo is the tracking state of one (zone, secondary) pair, served
// by --status so a stuck or lagging slave is visible on the master.
type LagInfo struct {
	Zone         string    `json:"zone"`
	Secondary    string    `json:"secondary"`
	Reachable    bool      `json:"reachable"`
	MasterSerial uint32    `json:"master_serial"`
	SlaveSerial  uint32    `json:"slave_serial"`
	Behind       bool      `json:"behind"`
	LastCheck    time.Time `json:"last_check"`
	Detail       string    `json:"detail,omitempty"`
}

// StartMonitor polls every secondary of every hosted primary zone for
// its SOA serial and records how it compares to ours. Runs only on a
// master (a node with secondaries); harmless otherwise (no targets).
func (mg *Manager) StartMonitor() {
	go func() {
		t := time.NewTicker(monitorInterval)
		defer t.Stop()
		mg.checkLag() // first pass right away
		for {
			select {
			case <-mg.stop:
				return
			case <-t.C:
				mg.checkLag()
			}
		}
	}()
}

func (mg *Manager) checkLag() {
	now := time.Now()
	fresh := map[string]LagInfo{}
	for _, ps := range mg.store.PrimaryStatuses() {
		for _, target := range ps.Secondaries {
			info := LagInfo{
				Zone:         ps.Apex,
				Secondary:    target,
				MasterSerial: ps.Serial,
				LastCheck:    now,
			}
			serial, err := mg.querySOA(ps.Apex, hostPort(target))
			if err != nil {
				info.Detail = err.Error()
			} else {
				info.Reachable = true
				info.SlaveSerial = serial
				info.Behind = serialNewer(ps.Serial, serial)
			}
			fresh[ps.Apex+"|"+target] = info
		}
	}
	mg.mu.Lock()
	mg.lag = fresh
	mg.mu.Unlock()
}

// LagSnapshot returns the latest lag state, sorted by zone then
// secondary. Empty when this node has no secondaries.
func (mg *Manager) LagSnapshot() []LagInfo {
	mg.mu.Lock()
	out := make([]LagInfo, 0, len(mg.lag))
	for _, info := range mg.lag {
		out = append(out, info)
	}
	mg.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].Zone != out[j].Zone {
			return out[i].Zone < out[j].Zone
		}
		return out[i].Secondary < out[j].Secondary
	})
	return out
}
