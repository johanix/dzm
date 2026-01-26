/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Shared chunk splitting and reassembly functions
 */

package tnm

import (
	"fmt"
	"math"

	"github.com/johanix/tdns/v2/core"
)

// SplitIntoCHUNKs splits data into CHUNK records of specified size
// Returns CHUNK records with 1-based sequence numbers (1, 2, 3, ..., total)
// Returns nil if the data would result in more than math.MaxUint16 chunks or if any chunk would exceed math.MaxUint16 bytes
func SplitIntoCHUNKs(data []byte, chunkSize int, format uint8) []*core.CHUNK {
	if chunkSize <= 0 {
		chunkSize = 60000 // Default
	}

	var chunks []*core.CHUNK
	total := len(data)
	numChunks := (total + chunkSize - 1) / chunkSize // Ceiling division

	// Check for integer overflow before converting to uint16
	if numChunks > math.MaxUint16 {
		return nil // Return nil if overflow would occur
	}
	numChunksUint16 := uint16(numChunks)

	for i := 0; i < numChunks; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > total {
			end = total
		}

		chunkData := make([]byte, end-start)
		copy(chunkData, data[start:end])

		// Check for integer overflow before converting to uint16
		if i+1 > math.MaxUint16 {
			return nil // Return nil if overflow would occur
		}
		if len(chunkData) > math.MaxUint16 {
			return nil // Return nil if overflow would occur
		}

		chunk := &core.CHUNK{
			Format:     format,
			HMACLen:    0, // No HMAC for data chunks
			HMAC:       nil,
			Sequence:   uint16(i + 1), // 1-based: 1, 2, 3, ..., N
			Total:      numChunksUint16,
			DataLength: uint16(len(chunkData)),
			Data:       chunkData,
		}
		chunks = append(chunks, chunk)
	}

	return chunks
}

// ReassembleCHUNKChunks reassembles CHUNK chunks into complete data
// Note: CHUNK uses 1-based sequence numbers (1, 2, 3, ..., total)
func ReassembleCHUNKChunks(chunks []*core.CHUNK) ([]byte, error) {
	if len(chunks) == 0 {
		return nil, fmt.Errorf("no chunks to reassemble")
	}

	// Get total from first chunk (all chunks should have same Total)
	total := int(chunks[0].Total)
	if total == 0 {
		return nil, fmt.Errorf("invalid chunk total: 0 (expected > 0 for data chunks)")
	}

	// Check for integer overflow before converting to uint16
	if total > math.MaxUint16 {
		return nil, fmt.Errorf("chunk total too large: %d (max: %d)", total, math.MaxUint16)
	}
	totalUint16 := uint16(total)

	if len(chunks) != total {
		return nil, fmt.Errorf("chunk count mismatch: expected %d, got %d", total, len(chunks))
	}

	// Sort chunks by sequence number
	// Note: CHUNK uses 1-based sequence numbers (1, 2, 3, ..., total)
	chunkMap := make(map[uint16]*core.CHUNK)
	for _, chunk := range chunks {
		// Validate sequence is in range [1, total] (1-based)
		if chunk.Sequence < 1 || int(chunk.Sequence) > total {
			return nil, fmt.Errorf("chunk sequence %d out of range (expected 1-%d)", chunk.Sequence, total)
		}
		if chunk.Total != totalUint16 {
			return nil, fmt.Errorf("chunk total mismatch: expected %d, got %d", total, chunk.Total)
		}
		chunkMap[chunk.Sequence] = chunk
	}

	// Reassemble in order (1-based: 1, 2, 3, ..., total)
	reassembled := make([]byte, 0)
	for i := uint16(1); i <= totalUint16; i++ {
		chunk, ok := chunkMap[i]
		if !ok {
			return nil, fmt.Errorf("missing chunk with sequence %d", i)
		}
		reassembled = append(reassembled, chunk.Data...)
	}

	return reassembled, nil
}
