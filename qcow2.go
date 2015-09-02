package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
)

func main() {
	flag.Parse()

	for _, arg := range flag.Args() {
		fh, err := os.Open(arg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[ERR] %q: %s\n", arg, err)
			os.Exit(1)
		}
		defer fh.Close()

		buf := make([]byte, Qcow2V2HeaderSize)
		size, err := fh.Read(buf)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[ERR] %q: %s\n", arg, err)
			os.Exit(1)
		}
		if size < Qcow2V2HeaderSize {
			fmt.Fprintf(os.Stderr, "[ERR] %q: short read\n", arg)
			os.Exit(1)
		}

		if bytes.Compare(buf[:4], Qcow2Magic) != 0 {
			fmt.Fprintf(os.Stderr, "[ERR] %q: Does not appear to be qcow file %#v %#v\n", arg, buf[:4], Qcow2Magic)
			os.Exit(1)
		}

		q := Header{
			Version:               Qcow2Version(be32(buf[4:8])),
			BackingFileOffset:     be64(buf[8:16]),
			BackingFileSize:       be32(buf[16:20]),
			ClusterBits:           be32(buf[20:24]),
			Size:                  be64(buf[24:32]),
			CryptMethod:           CryptMethod(be32(buf[32:36])),
			L1Size:                be32(buf[36:40]),
			L1TableOffset:         be64(buf[40:48]),
			RefcountTableOffset:   be64(buf[48:56]),
			RefcountTableClusters: be32(buf[56:60]),
			NbSnapshots:           be32(buf[60:64]),
			SnapshotsOffset:       be64(buf[64:72]),
			HeaderLength:          72, // v2 this is a standard length
		}

		if q.Version == 3 {
			size, err := fh.Read(buf[:Qcow2V3HeaderSize])
			if err != nil {
				fmt.Fprintf(os.Stderr, "[ERR] %q: %s\n", arg, err)
				os.Exit(1)
			}
			if size < Qcow2V3HeaderSize {
				fmt.Fprintf(os.Stderr, "[ERR] %q: short read\n", arg)
				os.Exit(1)
			}

			q.IncompatibleFeatures = be32(buf[0:8])
			q.CompatibleFeatures = be32(buf[8:16])
			q.AutoclearFeatures = be32(buf[16:24])
			q.RefcountOrder = be32(buf[24:28])
			q.HeaderLength = be32(buf[28:32])
		}
		fmt.Printf("%#v\n", q)
		fmt.Printf("IncompatibleFeatures: %b\n", q.IncompatibleFeatures)
		fmt.Printf("CompatibleFeatures: %b\n", q.CompatibleFeatures)

		// Process the extension header data
		buf = make([]byte, q.HeaderLength)
		size, err = fh.Read(buf)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[ERR] %q: %s\n", arg, err)
			os.Exit(1)
		}
		if size < q.HeaderLength {
			fmt.Fprintf(os.Stderr, "[ERR] %q: short read\n", arg)
			os.Exit(1)
		}
		for {
			t := HeaderExtensionType(be32(buf[:4]))
			if t == HdrExtEndOfArea {
				break
			}
			exthdr := ExtHeader{
				Type: t,
				Size: be32(buf[4:8]),
			}
			// XXX this may need a copy(), so the slice resuse doesn't corrupt
			exthdr.Data = buf[8 : 8+exthdr.Size]
			q.ExtHeaders = append(q.ExtHeaders, exthdr)

			round := exthdr.Size % 8
			buf = buf[8+exthdr.Size+round:]
		}

	}
}

func be32(b []byte) int {
	return int(binary.BigEndian.Uint32(b))
}

func be64(b []byte) int64 {
	return int64(binary.BigEndian.Uint64(b))
}

var (
	// Qcow2Magic is the front of the file fingerprint
	Qcow2Magic = []byte{0x51, 0x46, 0x49, 0xFB}

	// Qcow2V2HeaderSize is the image header at the beginning of the file
	Qcow2V2HeaderSize = 72

	// Qcow2V3HeaderSize is directly following the v2 header, up to 104
	Qcow2V3HeaderSize = 104 - Qcow2V2HeaderSize
)

type (
	// Qcow2Version number of this image. Valid versions are 2 or 3
	Qcow2Version int

	// CryptMethod is whether no encryption (0), or AES encryption (1)
	CryptMethod int

	// HeaderExtensionType indicators the the entries in the optional header area
	HeaderExtensionType int
)

const (
	HdrExtEndOfArea         HeaderExtensionType = 0x00000000
	HdrExtBackingFileFormat HeaderExtensionType = 0xE2792ACA
	HdrExtFeatureNameTable  HeaderExtensionType = 0x6803f857 // TODO needs processing for feature name table
	// any thing else is "other" and can be ignored
)

func (qcm CryptMethod) String() string {
	if qcm == 1 {
		return "AES"
	}
	return "none"
}

type Header struct {
	// magic [:4]
	Version               Qcow2Version // [4:8]
	BackingFileOffset     int64        // [8:16]
	BackingFileSize       int          // [16:20]
	ClusterBits           int          // [20:24]
	Size                  int64        // [24:32]
	CryptMethod           CryptMethod  // [32:36]
	L1Size                int          // [36:40]
	L1TableOffset         int64        // [40:48]
	RefcountTableOffset   int64        // [48:56]
	RefcountTableClusters int          // [56:60]
	NbSnapshots           int          // [60:64]
	SnapshotsOffset       int64        // [64:72]

	// v3
	IncompatibleFeatures int // [72:80] bitmask
	CompatibleFeatures   int // [80:88] bitmask
	AutoclearFeatures    int // [88:96] bitmask
	RefcountOrder        int // [96:100]
	HeaderLength         int // [100:104]

	// Header extensions
	ExtHeaders []ExtHeader
}

type ExtHeader struct {
	Type HeaderExtensionType
	Size int
	Data []byte
}
