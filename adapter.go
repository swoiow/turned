package turned

import (
	BF "github.com/bits-and-blooms/bloom/v3"
)

type bottleAdapter struct {
	BloomFilter  *BF.BloomFilter
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
		adapter.ContainsFunc = adapter.BloomFilter.TestString
	} else {
		adapter.ContainsFunc = adapter.mapTestString
	}
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
