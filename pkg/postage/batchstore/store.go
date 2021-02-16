// Copyright 2020 The Swarm Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package batchstore

import (
	"errors"
	"math/big"

	"github.com/ethersphere/bee/pkg/postage"
	"github.com/ethersphere/bee/pkg/storage"
)

const (
	batchKeyPrefix  = "batch"
	valueKeyPrefix  = "value"
	chainStateKey   = "chain"
	reserveStateKey = "reserve"
)

// store implements postage.Storer
type store struct {
	store         storage.StateStorer                     // State store backend to persist batches.
	cs            *postage.ChainState                     // the chain state
	rs            *reserveState                           // the reserve state
	unreserveFunc func(batchID []byte, depth uint8) error // unreserve function
}

// New constructs a new postage batch store.
// It initialises both chain state and reserve state from the persistent state store
func New(st storage.StateStorer) (postage.Storer, error) {
	cs := &postage.ChainState{}
	err := st.Get(chainStateKey, cs)
	if err != nil {
		if !errors.Is(err, storage.ErrNotFound) {
			return nil, err
		}
		cs = &postage.ChainState{
			Block: 0,
			Total: big.NewInt(0),
			Price: big.NewInt(0),
		}
	}
	rs := &reserveState{}
	err = st.Get(chainStateKey, rs)
	if err != nil {
		if !errors.Is(err, storage.ErrNotFound) {
			return nil, err
		}
		rs = &reserveState{
			Depth:    DefaultDepth,
			Core:     big.NewInt(0),
			Edge:     big.NewInt(0),
			Capacity: Capacity,
		}
	}
	return &store{st, cs, rs, nil}, nil
}

// Get returns a batch from the batchstore with the given ID.
func (s *store) Get(id []byte) (*postage.Batch, error) {
	b := &postage.Batch{}
	err := s.store.Get(batchKey(id), b)
	return b, err
}

// Put stores a given batch in the batchstore with the given ID.
func (s *store) Put(b *postage.Batch, value *big.Int, depth uint8) error {
	oldval := big.NewInt(0).Set(b.Value)
	err := s.store.Delete(valueKey(oldval, b.ID))
	if err != nil {
		return err
	}
	b.Value.Set(value)
	b.Depth = depth
	err = s.store.Put(valueKey(b.Value, b.ID), b.ID)
	if err != nil {
		return err
	}
	err = s.store.Put(batchKey(b.ID), b)
	if err != nil {
		return err
	}
	return s.updateValueChange(b.ID, depth, oldval, value)
}

// delete removes the batches with ids given as arguments.
func (s *store) delete(ids ...[]byte) error {
	for _, id := range ids {
		b, err := s.Get(id)
		if err != nil {
			return err
		}
		err = s.store.Delete(valueKey(b.Value, id))
		if err != nil {
			return err
		}
		err = s.store.Delete(batchKey(id))
		if err != nil {
			return err
		}
	}
	return nil
}

// PutChainState implements BatchStorer.
// It purges expired batches and unreserves underfunded ones before it
// stores the chain state in the batch store.
func (s *store) PutChainState(cs *postage.ChainState) error {
	s.cs = cs
	err := s.purgeExpired()
	if err != nil {
		return err
	}
	return s.store.Put(chainStateKey, cs)
}

// GetChainState implements BatchStorer. It returns the stored chain state from
// the batch store.
func (s *store) GetChainState() *postage.ChainState {
	return s.cs
}

// batchKey returns the index key for the batch ID used in the by-ID batch index.
func batchKey(id []byte) string {
	return batchKeyPrefix + string(id)
}

// batchKey returns the index key for the batch ID used in the by-ID batch index.
func valueKey(val *big.Int, id []byte) string {
	value := make([]byte, 32)
	val.FillBytes(value) // zero-extended big-endian byte slice
	// return valueKeyPrefix + string(append(value, id...))
	return valueKeyPrefix + string(value) + string(id)
}

// valueKeyToID extracts the batch ID from a value key - used in value-based iteration
func valueKeyToID(key []byte) []byte {
	l := len(key)
	return key[l-32 : l]
}
