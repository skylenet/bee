// Copyright 2020 The Swarm Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// the reserve serves to maintain chunks in the area of responsibility
// it has two components
// -  the batchstore reserve which maintains information about batches, their values, priorities and synchronises with the blockchain
// - the localstore which stores chunks and manages garbage collection
//
// when a new chunk arrives in the localstore, the batchstore reserve is asked to check
// the batch used in the postage stamp attached to the chunk.
// Depending on the value of the batch (reserve depth of the batch), the localstore
// either pins the chunk (thereby protecting it from garbage collection) or not.
// the chunk stays pinned until it is 'unreserved' based on changes in relative priority of the batch it belongs to
//
// the atomic db operation is unreserving a batch down to a depth
// the intended semantics of unreserve is to unpin the chunks
// in the relevant POs, belonging to the batch and (unless they are otherwise pinned)
// allow  them  to be gargage collected.
//
// the rules of the reserve
// - if batch a is unreserved and val(b) <  val(a) then b is unreserved on any po
// - if a batch is unreserved on po  p, then  it is unreserved also on any p'<p
// - batch size based on fully filled the reserve should not  exceed Capacity
// - batch reserve is maximally utilised, i.e, cannot be extended and have 1-3 remain true
package batchstore

import (
	"math/big"

	"github.com/ethersphere/bee/pkg/swarm"
)

// DefaultDepth is the initial depth for the reserve
const DefaultDepth = 5

// Capacity = number of chunks in reserve
var Capacity = exp2(23)

var big1 = big.NewInt(1)

// reserveState records the state and is persisted in the state store
type reserveState struct {
	Depth    uint8    `json:"depth"`    // Radius of responsibility
	Capacity int64    `json:"capacity"` // size of the reserve -  number of chunks
	Edge     *big.Int `json:"edge"`     // lower value limit for edge layer = the further half of chunks
	Core     *big.Int `json:"core"`     // lower value limit for core layer = the closer half of chunks
}

// SetUnreserve sets the unreserve hook (a localstore atomic operation)
// should be used at init, its not in the constructor bc localstore depends on BatchStore
func (s *store) SetUnreserve(f func(batchID []byte, depth uint8) error) {
	s.unreserveFunc = f
}

// unreserve is called when the batchstore decides not to reserve a batch on a PO
// i.e.  chunk of  the batch in bins [0 upto PO] (closed  interval) are unreserved
func (s *store) unreserve(batchID []byte, depth uint8) error {
	return s.unreserveFunc(batchID, depth)
}

func (s *store) purgeExpired() error {
	var toDelete [][]byte
	err := s.store.Iterate(valueKeyPrefix, func(key, _ []byte) (bool, error) {
		b, err := s.Get(valueKeyToID(key))
		if err != nil {
			return true, err
		}
		if b.Value.Cmp(s.rs.Core) >= 0 {
			return true, nil
		}
		err = s.unreserve(b.ID, swarm.MaxPO)
		if err != nil {
			return true, err
		}
		// if batch has no value then delete it
		if b.Value.Cmp(s.cs.Total) <= 0 {
			toDelete = append(toDelete, b.ID)
		}
		return false, nil
	})
	if err != nil {
		return err
	}
	return s.delete(toDelete...)
}

type change struct {
	old, new int
}

func newChange(oldv, newv, lower, higher *big.Int) *change {
	return &change{
		old: cmp(oldv, lower, higher),
		new: cmp(newv, lower, higher),
	}
}

func cmp(x, lower, higher *big.Int) int {
	if x.Cmp(lower) < 0 || x.Cmp(big.NewInt(0)) == 0 {
		return -1
	}
	if x.Cmp(higher) < 0 {
		return 0
	}
	return 1
}

func (ch *change) changed() bool {
	return ch.old != ch.new
}

func (ch *change) increased() bool {
	return ch.old < ch.new
}

func (ch *change) double() bool {
	return ch.old+ch.new == 0
}

func (ch *change) out() bool {
	return ch.new < 0
}

// updateReserveState manages what chunks of which batch are allocated to the reserve
func (s *store) updateValueChange(id []byte, depth uint8, oldValue, newValue *big.Int) error {
	defer func() {
		if s.rs.Capacity > 0 && s.rs.Core.Cmp(newValue) > 0 {
			s.rs.Core.Set(newValue)
		}
	}()
	ch := newChange(oldValue, newValue, s.rs.Core, s.rs.Edge)
	// if values unchanged then limits dont change
	if !ch.changed() {
		return nil
	}
	half := exp2(depth - s.rs.Depth - 1)
	// if value drops out then available capacity is increased with the batch's size within neighbourhood
	if ch.out() {
		s.rs.Capacity += half
		if ch.double() {
			s.rs.Capacity += half
		}
		// the chunks of this batch are unreserved in all po bins down to MaxPO
		return s.unreserve(id, swarm.MaxPO)
	}
	// if value decreased and fell below the edge limit, then the freed capacity is added
	if !ch.increased() {
		s.rs.Capacity += half
		// the chunks of this batch are unreserved in PO depth
		return s.unreserve(id, s.rs.Depth)
	}
	// otherwise value increased and we need to make capacity for its size
	s.rs.Capacity -= half
	// double means it got from no reserve to reserve upto full depth
	if ch.double() {
		s.rs.Capacity -= half
	}
	if err := s.unreserve(id, s.rs.Depth-uint8(ch.new)); err != nil {
		return err
	}
	return s.release()
}

// release is responsible  to bring capacity back to positive by unreserving lowest priority batches
func (s *store) release() error {
	if s.rs.Capacity > 0 {
		return nil
	}
	err := s.store.Iterate(valueKeyPrefix, func(key, _ []byte) (bool, error) {
		b, err := s.Get(valueKeyToID(key))
		if err != nil {
			return true, err
		}
		//  FIXME: this is needed only because  the statestoore iterator does not allow seek, only prefix
		//  so we  need  to  page through all  the batches until edge limit   is reached
		if b.Value.Cmp(s.rs.Edge) < 0 {
			return false, nil
		}
		// stop iteration  only  if  we consumed all batches of the same value as the one that put capacity above zero
		if s.rs.Capacity >= 0 && s.rs.Edge.Cmp(b.Value) != 0 {
			return true, nil
		}
		// unreserve edge PO of the lowest priority batch  until capacity is back to positive
		s.rs.Capacity += exp2(b.Depth - s.rs.Depth - 1)
		s.rs.Edge.Set(b.Value)
		return false, s.unreserve(b.ID, s.rs.Depth)
	})
	if err != nil {
		return err
	}
	// add 1 to edge limit value so we dont hit on the same batch next time we iterate
	s.rs.Edge.Add(s.rs.Edge, big1)
	// if we consumed all batches, ie. we unreserved all chunks on the edge = depth PO
	//  then its time to  increase depth
	if s.rs.Capacity < 0 {
		s.rs.Depth++
		s.rs.Edge.Set(s.rs.Core) // reset edge limit to core limit
		return s.release()
	}
	return s.store.Put(reserveStateKey, s.rs)
}

// exp2 returns the e-th power of 2
func exp2(e uint8) int64 {
	if e == 0 {
		return 1
	}
	b := int64(2)
	for i := uint8(1); i < e; i++ {
		b *= 2
	}
	return b
}
