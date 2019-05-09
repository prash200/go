// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pe

import (
	"encoding/binary"
	"fmt"
	"io"
)

const COFFSymbolSize = 18

// COFFSymbol represents single COFF symbol table record.
type COFFSymbol struct {
	Name               [8]uint8
	Value              uint32
	SectionNumber      int16
	Type               uint16
	StorageClass       uint8
	NumberOfAuxSymbols uint8
}

func readCOFFSymbols(fh *FileHeader, r io.ReadSeeker) ([]COFFSymbol, error) {
	if fh.PointerToSymbolTable == 0 {
		return nil, nil
	}
	if fh.NumberOfSymbols <= 0 {
		return nil, nil
	}
	_, err := r.Seek(int64(fh.PointerToSymbolTable), seekStart)
	if err != nil {
		return nil, fmt.Errorf("fail to seek to symbol table: %v", err)
	}
	syms := make([]COFFSymbol, fh.NumberOfSymbols)
	err = binary.Read(r, binary.LittleEndian, syms)
	if err != nil {
		return nil, fmt.Errorf("fail to read symbol table: %v", err)
	}
	return syms, nil
}

// isSymNameOffset checks symbol name if it is encoded as offset into string table.
func isSymNameOffset(name [8]byte) (bool, uint32) {
	if name[0] == 0 && name[1] == 0 && name[2] == 0 && name[3] == 0 {
		return true, binary.LittleEndian.Uint32(name[4:])
	}
	return false, 0
}

// FullName finds real name of symbol sym. Normally name is stored
// in sym.Name, but if it is longer then 8 characters, it is stored
// in COFF string table st instead.
func (sym *COFFSymbol) FullName(st StringTable) (string, error) {
	if ok, offset := isSymNameOffset(sym.Name); ok {
		return st.String(offset)
	}
	return cstring(sym.Name[:]), nil
}

func removeAuxSymbols(allsyms []COFFSymbol, st StringTable) ([]*Symbol, error) {
	if len(allsyms) == 0 {
		return nil, nil
	}
	syms := make([]*Symbol, 0)
	aux := uint8(0)
	for _, sym := range allsyms {
		if aux > 0 {
			aux--
			continue
		}
		name, err := sym.FullName(st)
		if err != nil {
			return nil, err
		}
		aux = sym.NumberOfAuxSymbols
		s := &Symbol{
			Name:          name,
			Value:         sym.Value,
			SectionNumber: sym.SectionNumber,
			Type:          sym.Type,
			StorageClass:  sym.StorageClass,
		}
		syms = append(syms, s)
	}
	return syms, nil
}

// Symbol is similar to COFFSymbol with Name field replaced
// by Go string. Symbol also does not have NumberOfAuxSymbols.
type Symbol struct {
	Name          string
	Value         uint32
	SectionNumber int16
	Type          uint16
	StorageClass  uint8
}

func readOptionalHeader(r io.ReadSeeker, sz uint16) (interface{}, error) {
	// If optional header size is 0, return empty optional header.
	if sz == 0 {
		return nil, nil
	}

	var (
		ohMagic   uint16
		ohMagicSz = binary.Size(ohMagic)
	)

	// If optional header size is greater than 0 but less than its magic size, return error.
	if sz < uint16(ohMagicSz) {
		return nil, fmt.Errorf("optional header size is less than optional header magic size")
	}

	// First just read optional header magic.
	if err := binary.Read(r, binary.LittleEndian, &ohMagic); err != nil {
		return nil, fmt.Errorf("failure to read optional header magic: %v", err)
	}

	// Seek back by optional header magic's size.
	r.Seek(-int64(ohMagicSz), seekCurrent)

	switch ohMagic {
	case 0x10b: // PE32
		var (
			oh32Base   optionalHeader32Base
			oh32BaseSz = binary.Size(oh32Base)
		)
		if sz < uint16(oh32BaseSz) {
			return nil, fmt.Errorf("optional header size(%d) is less base size (%d) for PE32 optional header", sz, oh32BaseSz)
		}

		if err := binary.Read(r, binary.LittleEndian, &oh32Base); err != nil {
			return nil, fmt.Errorf("failure to read PE32 optional header: %v", err)
		}

		dd, err := readDataDirectories(r, sz-uint16(oh32BaseSz), oh32Base.NumberOfRvaAndSizes)
		if err != nil {
			return nil, err
		}

		oh32 := new(OptionalHeader32)
		oh32.init(oh32Base, dd)

		return oh32, nil
	case 0x20b: // PE32+
		var (
			oh64Base   optionalHeader64Base
			oh64BaseSz = binary.Size(oh64Base)
		)
		if sz < uint16(oh64BaseSz) {
			return nil, fmt.Errorf("optional header size(%d) is less base size (%d) for PE32+ optional header", sz, oh64BaseSz)
		}

		if err := binary.Read(r, binary.LittleEndian, &oh64Base); err != nil {
			return nil, fmt.Errorf("failure to read PE32+ optional header: %v", err)
		}

		dd, err := readDataDirectories(r, sz-uint16(oh64BaseSz), oh64Base.NumberOfRvaAndSizes)
		if err != nil {
			return nil, err
		}

		oh64 := new(OptionalHeader64)
		oh64.init(oh64Base, dd)

		return oh64, nil
	default:
		return nil, fmt.Errorf("optional header has unexpected Magic of 0x%x", ohMagic)
	}
}

func readDataDirectories(r io.ReadSeeker, sz uint16, n uint32) ([]DataDirectory, error) {
	ddSz := binary.Size(DataDirectory{})
	if uint32(sz) != n*uint32(ddSz) {
		return nil, fmt.Errorf("size of data directories(%d) is inconsistent with number of data directories(%d)", sz, n)
	}

	dd := make([]DataDirectory, n)
	if err := binary.Read(r, binary.LittleEndian, dd); err != nil {
		return nil, fmt.Errorf("failure to read data directories: %v", err)
	}

	return dd, nil
}
