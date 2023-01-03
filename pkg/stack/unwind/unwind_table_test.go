// Copyright 2022 The Parca Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package unwind

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/go-kit/log"
	"github.com/stretchr/testify/require"
	"os"
	"testing"

	"github.com/parca-dev/parca-agent/internal/dwarf/frame"
)

func TestBuildUnwindTable(t *testing.T) {
	logger := log.NewNopLogger()
	utb := NewUnwindTableBuilder(logger)

	fdes, err := utb.readFDEs("../../../testdata/out/basic-cpp")
	require.NoError(t, err)

	unwindTable := buildUnwindTable(fdes)
	require.Equal(t, 38, len(unwindTable))

	require.Equal(t, uint64(0x401020), unwindTable[0].Loc)
	require.Equal(t, uint64(0x40118e), unwindTable[len(unwindTable)-1].Loc)

	require.Equal(t, frame.DWRule{Rule: frame.RuleOffset, Offset: -8}, unwindTable[0].RA)
	require.Equal(t, frame.DWRule{Rule: frame.RuleCFA, Reg: 0x7, Offset: 8}, unwindTable[0].CFA)
	require.Equal(t, frame.DWRule{Rule: frame.RuleUnknown, Reg: 0x0, Offset: 0}, unwindTable[0].RBP)
}

func TestXXX(t *testing.T) {
	path, err := os.Getwd()
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(path)

	logger := log.NewNopLogger()
	utb := NewUnwindTableBuilder(logger)

	fdes, err := utb.readFDEs("./cockroach")
	require.NoError(t, err)

	unwindTable := buildUnwindTable(fdes)
	fmt.Printf("rows in unwind table: %d\n", len(unwindTable))
	byteOrder := binary.LittleEndian
	SerializeUnwindTable(unwindTable, byteOrder)

	//require.Equal(t, 38, len(unwindTable))
	//
	//require.Equal(t, uint64(0x401020), unwindTable[0].Loc)
	//require.Equal(t, uint64(0x40118e), unwindTable[len(unwindTable)-1].Loc)
	//
	//require.Equal(t, frame.DWRule{Rule: frame.RuleOffset, Offset: -8}, unwindTable[0].RA)
	//require.Equal(t, frame.DWRule{Rule: frame.RuleCFA, Reg: 0x7, Offset: 8}, unwindTable[0].CFA)
	//require.Equal(t, frame.DWRule{Rule: frame.RuleUnknown, Reg: 0x0, Offset: 0}, unwindTable[0].RBP)
}

var rbpOffsetResult int64

func benchmarkParsingDwarfUnwindInformation(b *testing.B, executable string) {
	b.Helper()
	b.ReportAllocs()

	logger := log.NewNopLogger()
	var rbpOffset int64
	utb := NewUnwindTableBuilder(logger)

	for n := 0; n < b.N; n++ {
		fdes, err := utb.readFDEs(executable)
		if err != nil {
			panic("could not read FDEs")
		}

		for _, fde := range fdes {
			frameContext := frame.ExecuteDwarfProgram(fde, nil)
			for insCtx := frameContext.Next(); frameContext.HasNext(); insCtx = frameContext.Next() {
				unwindRow := unwindTableRow(insCtx)
				if unwindRow.RBP.Rule == frame.RuleUndefined || unwindRow.RBP.Offset == 0 {
					// u
					rbpOffset = 0
				} else {
					rbpOffset = unwindRow.RBP.Offset
				}
			}
		}
	}
	// Make sure that the compiler won't optimize out the benchmark.
	rbpOffsetResult = rbpOffset
}

func BenchmarkParsingLibcUnwindInformation(b *testing.B) {
	benchmarkParsingDwarfUnwindInformation(b, "../../../testdata/vendored/libc.so.6")
}

func BenchmarkParsingRedpandaUnwindInformation(b *testing.B) {
	benchmarkParsingDwarfUnwindInformation(b, "../../../testdata/vendored/redpanda")
}

const (
	unwindTableMaxEntries = 100
	maxUnwindTableSize    = 250 * 1000 // Always needs to be sync with MAX_UNWIND_TABLE_SIZE in the BPF program.
	unwindTableShardCount = 6          // Always needs to be sync with MAX_SHARDS in the BPF program.
	maxUnwindSize         = maxUnwindTableSize * unwindTableShardCount
)

type BpfCfaType uint16

const (
	CfaRegisterUndefined BpfCfaType = iota
	CfaRegisterRbp
	CfaRegisterRsp
	CfaRegisterExpression
)

type BpfRbpType uint16

const (
	RbpRuleOffsetUnchanged BpfRbpType = iota
	RbpRuleOffset
	RbpRuleRegister
	RbpRegisterExpression
)

func SerializeUnwindTable(ut UnwindTable, byteOrder binary.ByteOrder) error {
	buf := new(bytes.Buffer)

	if len(ut) >= maxUnwindSize {
		return fmt.Errorf("maximum unwind table size reached. Table size %d, but max size is %d", len(ut), maxUnwindSize)
	}

	// Range-partition the unwind table in the different shards.
	shardIndex := 0
	for i := 0; i < len(ut); i += maxUnwindTableSize {
		upTo := i + maxUnwindTableSize
		if upTo > len(ut) {
			upTo = len(ut)
		}

		chunk := ut[i:upTo]

		// Write `.low_pc`
		if err := binary.Write(buf, byteOrder, chunk[0].Loc); err != nil {
			return fmt.Errorf("write the number of rows: %w", err)
		}
		// Write `.high_pc`.
		if err := binary.Write(buf, byteOrder, chunk[len(chunk)-1].Loc); err != nil {
			return fmt.Errorf("write the number of rows: %w", err)
		}
		// Write number of rows `.table_len`.
		if err := binary.Write(buf, byteOrder, uint64(len(chunk))); err != nil {
			return fmt.Errorf("write the number of rows: %w", err)
		}
		// Write padding.
		if err := binary.Write(buf, byteOrder, uint64(0)); err != nil {
			return fmt.Errorf("write the number of rows: %w", err)
		}
		for _, row := range chunk {
			// Right now we only support x86_64, where the return address position
			// is specified in the ABI, so we don't write it.

			// Write Program Counter (PC).
			if err := binary.Write(buf, byteOrder, row.Loc); err != nil {
				return fmt.Errorf("write the program counter: %w", err)
			}

			// Write __reserved_do_not_use.
			if err := binary.Write(buf, byteOrder, uint16(0)); err != nil {
				return fmt.Errorf("write CFA register bytes: %w", err)
			}

			var CfaRegister uint8
			var RbpRegister uint8
			var CfaOffset int16
			var RbpOffset int16

			// CFA.
			switch row.CFA.Rule {
			case frame.RuleCFA:
				if row.CFA.Reg == frame.X86_64FramePointer {
					CfaRegister = uint8(CfaRegisterRbp)
				} else if row.CFA.Reg == frame.X86_64StackPointer {
					CfaRegister = uint8(CfaRegisterRsp)
				}
				CfaOffset = int16(row.CFA.Offset)
			case frame.RuleExpression:
				CfaRegister = uint8(CfaRegisterExpression)
				CfaOffset = int16(ExpressionIdentifier(row.CFA.Expression))

			default:
				return fmt.Errorf("CFA rule is not valid. This should never happen")
			}

			// Frame pointer.
			switch row.RBP.Rule {
			case frame.RuleUndefined:
			case frame.RuleOffset:
				RbpRegister = uint8(RbpRuleOffset)
				RbpOffset = int16(row.RBP.Offset)
			case frame.RuleRegister:
				RbpRegister = uint8(RbpRuleRegister)
			case frame.RuleExpression:
				RbpRegister = uint8(RbpRegisterExpression)
			}

			// Write CFA type (.cfa_type).
			if err := binary.Write(buf, byteOrder, CfaRegister); err != nil {
				return fmt.Errorf("write CFA register bytes: %w", err)
			}

			// Write frame pointer type (.rbp_type).
			if err := binary.Write(buf, byteOrder, RbpRegister); err != nil {
				return fmt.Errorf("write CFA register bytes: %w", err)
			}

			// Write CFA offset (.cfa_offset).
			if err := binary.Write(buf, byteOrder, CfaOffset); err != nil {
				return fmt.Errorf("write CFA offset bytes: %w", err)
			}

			// Write frame pointer offset (.rbp_offset).
			if err := binary.Write(buf, byteOrder, RbpOffset); err != nil {
				return fmt.Errorf("write RBP offset bytes: %w", err)
			}
		}

		//// Set (PID, shard ID) -> unwind table for each shard.
		//keyBuf := new(bytes.Buffer)
		//if err := binary.Write(keyBuf, byteOrder, int32(pid)); err != nil {
		//	return fmt.Errorf("write RBP offset bytes: %w", err)
		//}
		//if err := binary.Write(keyBuf, byteOrder, int32(shardIndex)); err != nil {
		//	return fmt.Errorf("write RBP offset bytes: %w", err)
		//}

		//if err := m.unwindTables.Update(unsafe.Pointer(&keyBuf.Bytes()[0]), unsafe.Pointer(&buf.Bytes()[0])); err != nil {
		//	return fmt.Errorf("update unwind tables: %w", err)
		//}
		err := os.WriteFile(
			fmt.Sprintf("unwind-table-shard-%d", shardIndex), buf.Bytes(), 0644)
		if err != nil {
			return err
		}
		shardIndex++
		buf.Reset()
	}

	// HACK(javierhonduco): remove this.
	// Debug stuff to compare this with the BPF program's view of the world.
	/* printRow := func(w io.Writer, pt unwind.UnwindTable, index int) {
		cfaInfo := ""
		switch ut[index].CFA.Rule {
		case frame.RuleCFA:
			cfaInfo = fmt.Sprintf("CFA Reg: %d Offset:%d", ut[index].CFA.Reg, ut[index].CFA.Offset)
		case frame.RuleExpression:
			cfaInfo = "CFA exp"
		default:
			panic("CFA rule is not valid. This should never happen.")
		}

		fmt.Fprintf(w, "\trow[%d]. Loc: %x, %s, $rbp: %d\n", index, pt[index].Loc, cfaInfo, pt[index].RBP.Offset)
	}

	fmt.Fprintf(os.Stdout, "\t- Total entries %d\n\n", len(ut))
	printRow(os.Stdout, ut, 0)
	printRow(os.Stdout, ut, 1)
	printRow(os.Stdout, ut, 2)
	printRow(os.Stdout, ut, 6)
	printRow(os.Stdout, ut, len(ut)-1) */

	return nil
}
