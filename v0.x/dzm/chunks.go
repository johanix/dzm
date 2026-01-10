/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Shared chunk splitting and reassembly functions
 */

package dzm

import (
	"fmt"

	"github.com/johanix/tdns/v0.x/tdns/core"
)

// SplitIntoChunks splits data into chunks of specified size
func SplitIntoChunks(data []byte, chunkSize int) []*core.OLDCHUNK {
	if chunkSize <= 0 {
		chunkSize = 60000 // Default
	}

	var chunks []*core.OLDCHUNK
	total := len(data)
	numChunks := (total + chunkSize - 1) / chunkSize // Ceiling division

	for i := 0; i < numChunks; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > total {
			end = total
		}

		chunkData := make([]byte, end-start)
		copy(chunkData, data[start:end])

		chunk := &core.OLDCHUNK{
			Sequence: uint16(i),
			Total:    uint16(numChunks),
			Data:     chunkData,
		}
		chunks = append(chunks, chunk)
	}

	return chunks
}

// ReassembleChunks reassembles OLDCHUNK chunks into the complete base64-encoded data
func ReassembleChunks(chunks []*core.OLDCHUNK) ([]byte, error) {
	if len(chunks) == 0 {
		return nil, fmt.Errorf("no chunks to reassemble")
	}

	total := int(chunks[0].Total)
	if len(chunks) != total {
		return nil, fmt.Errorf("chunk count mismatch: expected %d, got %d", total, len(chunks))
	}

	// Sort chunks by sequence number
	chunkMap := make(map[uint16]*core.OLDCHUNK)
	for _, chunk := range chunks {
		if int(chunk.Sequence) >= total {
			return nil, fmt.Errorf("chunk sequence %d out of range (max %d)", chunk.Sequence, total-1)
		}
		chunkMap[chunk.Sequence] = chunk
	}

	// Reassemble in order
	reassembled := make([]byte, 0)
	for i := uint16(0); i < uint16(total); i++ {
		chunk, ok := chunkMap[i]
		if !ok {
			return nil, fmt.Errorf("missing chunk %d", i)
		}
		reassembled = append(reassembled, chunk.Data...)
	}

	return reassembled, nil
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
		if chunk.Total != uint16(total) {
			return nil, fmt.Errorf("chunk total mismatch: expected %d, got %d", total, chunk.Total)
		}
		chunkMap[chunk.Sequence] = chunk
	}

	// Reassemble in order (1-based: 1, 2, 3, ..., total)
	reassembled := make([]byte, 0)
	for i := uint16(1); i <= uint16(total); i++ {
		chunk, ok := chunkMap[i]
		if !ok {
			return nil, fmt.Errorf("missing chunk with sequence %d", i)
		}
		reassembled = append(reassembled, chunk.Data...)
	}

	return reassembled, nil
}
