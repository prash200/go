// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pe

type FileHeader struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type DataDirectory struct {
	VirtualAddress uint32
	Size           uint32
}

// Have to define optionalHeader32Base and optionalHeader64Base structs to keep api checker tool happy.
// The api checker tool doesn't understand promoted fields, so if these structs are embeded in 
// OptionalHeader32 and OptionalHeader64 structs, it throws an error.
// As a result, defining these unexported structs to be used by binary.Read() (ref. symbol.go)
// Also defined unexported init methods on OptionalHeader32 and OptionalHeader64 structs to initialize
// them from corresponding base structs
type optionalHeader32Base struct {
	Magic                       uint16
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	BaseOfData                  uint32
	ImageBase                   uint32
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint32
	SizeOfStackCommit           uint32
	SizeOfHeapReserve           uint32
	SizeOfHeapCommit            uint32
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
}

type OptionalHeader32 struct {
	Magic                       uint16
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	BaseOfData                  uint32
	ImageBase                   uint32
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint32
	SizeOfStackCommit           uint32
	SizeOfHeapReserve           uint32
	SizeOfHeapCommit            uint32
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory               [16]DataDirectory
}

func (o *OptionalHeader32) init(base optionalHeader32Base, dd []DataDirectory) {
	o.Magic = base.Magic
	o.MajorLinkerVersion = base.MajorLinkerVersion
	o.MinorLinkerVersion = base.MinorLinkerVersion
	o.SizeOfCode = base.SizeOfCode
	o.SizeOfInitializedData = base.SizeOfInitializedData
	o.SizeOfUninitializedData = base.SizeOfUninitializedData
	o.AddressOfEntryPoint = base.AddressOfEntryPoint
	o.BaseOfCode = base.BaseOfCode
	o.BaseOfData = base.BaseOfData
	o.ImageBase = base.ImageBase
	o.SectionAlignment = base.SectionAlignment
	o.FileAlignment = base.FileAlignment
	o.MajorOperatingSystemVersion = base.MajorOperatingSystemVersion
	o.MinorOperatingSystemVersion = base.MinorOperatingSystemVersion
	o.MajorImageVersion = base.MajorImageVersion
	o.MinorImageVersion = base.MinorImageVersion
	o.MajorSubsystemVersion = base.MajorSubsystemVersion
	o.MinorSubsystemVersion = base.MinorSubsystemVersion
	o.Win32VersionValue = base.Win32VersionValue
	o.SizeOfImage = base.SizeOfImage
	o.SizeOfHeaders = base.SizeOfHeaders
	o.CheckSum = base.CheckSum
	o.Subsystem = base.Subsystem
	o.DllCharacteristics = base.DllCharacteristics
	o.SizeOfStackReserve = base.SizeOfStackReserve
	o.SizeOfStackCommit = base.SizeOfStackCommit
	o.SizeOfHeapReserve = base.SizeOfHeapReserve
	o.SizeOfHeapCommit = base.SizeOfHeapCommit
	o.LoaderFlags = base.LoaderFlags
	o.NumberOfRvaAndSizes = base.NumberOfRvaAndSizes

	copy(o.DataDirectory[:], dd)
}

type optionalHeader64Base struct {
	Magic                       uint16
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
}

type OptionalHeader64 struct {
	Magic                       uint16
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory               [16]DataDirectory
}

func (o *OptionalHeader64) init(base optionalHeader64Base, dd []DataDirectory) {
	o.Magic = base.Magic
	o.MajorLinkerVersion = base.MajorLinkerVersion
	o.MinorLinkerVersion = base.MinorLinkerVersion
	o.SizeOfCode = base.SizeOfCode
	o.SizeOfInitializedData = base.SizeOfInitializedData
	o.SizeOfUninitializedData = base.SizeOfUninitializedData
	o.AddressOfEntryPoint = base.AddressOfEntryPoint
	o.BaseOfCode = base.BaseOfCode
	o.ImageBase = base.ImageBase
	o.SectionAlignment = base.SectionAlignment
	o.FileAlignment = base.FileAlignment
	o.MajorOperatingSystemVersion = base.MajorOperatingSystemVersion
	o.MinorOperatingSystemVersion = base.MinorOperatingSystemVersion
	o.MajorImageVersion = base.MajorImageVersion
	o.MinorImageVersion = base.MinorImageVersion
	o.MajorSubsystemVersion = base.MajorSubsystemVersion
	o.MinorSubsystemVersion = base.MinorSubsystemVersion
	o.Win32VersionValue = base.Win32VersionValue
	o.SizeOfImage = base.SizeOfImage
	o.SizeOfHeaders = base.SizeOfHeaders
	o.CheckSum = base.CheckSum
	o.Subsystem = base.Subsystem
	o.DllCharacteristics = base.DllCharacteristics
	o.SizeOfStackReserve = base.SizeOfStackReserve
	o.SizeOfStackCommit = base.SizeOfStackCommit
	o.SizeOfHeapReserve = base.SizeOfHeapReserve
	o.SizeOfHeapCommit = base.SizeOfHeapCommit
	o.LoaderFlags = base.LoaderFlags
	o.NumberOfRvaAndSizes = base.NumberOfRvaAndSizes

	copy(o.DataDirectory[:], dd)
}

const (
	IMAGE_FILE_MACHINE_UNKNOWN   = 0x0
	IMAGE_FILE_MACHINE_AM33      = 0x1d3
	IMAGE_FILE_MACHINE_AMD64     = 0x8664
	IMAGE_FILE_MACHINE_ARM       = 0x1c0
	IMAGE_FILE_MACHINE_ARMNT     = 0x1c4
	IMAGE_FILE_MACHINE_ARM64     = 0xaa64
	IMAGE_FILE_MACHINE_EBC       = 0xebc
	IMAGE_FILE_MACHINE_I386      = 0x14c
	IMAGE_FILE_MACHINE_IA64      = 0x200
	IMAGE_FILE_MACHINE_M32R      = 0x9041
	IMAGE_FILE_MACHINE_MIPS16    = 0x266
	IMAGE_FILE_MACHINE_MIPSFPU   = 0x366
	IMAGE_FILE_MACHINE_MIPSFPU16 = 0x466
	IMAGE_FILE_MACHINE_POWERPC   = 0x1f0
	IMAGE_FILE_MACHINE_POWERPCFP = 0x1f1
	IMAGE_FILE_MACHINE_R4000     = 0x166
	IMAGE_FILE_MACHINE_SH3       = 0x1a2
	IMAGE_FILE_MACHINE_SH3DSP    = 0x1a3
	IMAGE_FILE_MACHINE_SH4       = 0x1a6
	IMAGE_FILE_MACHINE_SH5       = 0x1a8
	IMAGE_FILE_MACHINE_THUMB     = 0x1c2
	IMAGE_FILE_MACHINE_WCEMIPSV2 = 0x169
)

// IMAGE_DIRECTORY_ENTRY constants
const (
	IMAGE_DIRECTORY_ENTRY_EXPORT         = 0
	IMAGE_DIRECTORY_ENTRY_IMPORT         = 1
	IMAGE_DIRECTORY_ENTRY_RESOURCE       = 2
	IMAGE_DIRECTORY_ENTRY_EXCEPTION      = 3
	IMAGE_DIRECTORY_ENTRY_SECURITY       = 4
	IMAGE_DIRECTORY_ENTRY_BASERELOC      = 5
	IMAGE_DIRECTORY_ENTRY_DEBUG          = 6
	IMAGE_DIRECTORY_ENTRY_ARCHITECTURE   = 7
	IMAGE_DIRECTORY_ENTRY_GLOBALPTR      = 8
	IMAGE_DIRECTORY_ENTRY_TLS            = 9
	IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    = 10
	IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   = 11
	IMAGE_DIRECTORY_ENTRY_IAT            = 12
	IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   = 13
	IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14
)
