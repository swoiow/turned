package turned

import (
	cuckoo "github.com/seiflotfy/cuckoofilter"
)

type bottleAdapter struct {
	BloomFilter  *cuckoo.Filter
	HashMap      map[string]bool
	ContainsFunc func(data string) bool
}

func NewAdapter() *bottleAdapter {
	return &bottleAdapter{
		BloomFilter: nil,
		HashMap:     map[string]bool{},
	}
}

func (adapter *bottleAdapter) setupContainsFunc() {
	if adapter.BloomFilter != nil {
		adapter.ContainsFunc = adapter.lookup
	} else {
		adapter.ContainsFunc = adapter.mapTestString
	}
}

func (adapter *bottleAdapter) lookup(s string) bool {
	return adapter.BloomFilter.Lookup([]byte(s))
}

func (adapter *bottleAdapter) Contains(s string) bool {
	return adapter.ContainsFunc(s)
}

func (adapter *bottleAdapter) mapTestString(s string) bool {
	return adapter.HashMap[s]
}

func (adapter *bottleAdapter) mapAddString(s string) {
	adapter.HashMap[s] = true
}
