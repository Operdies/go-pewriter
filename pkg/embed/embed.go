package embed

import (
	"encoding/binary"
)

const IMAGE_DIRECTORY_ENTRY_SECURITY = 4

var quietFlag = false

type DataDirectory struct {
	VirtualAddress uint32
	Size           uint32
}

func readUint16(data []byte, offset uint32) uint16 {
	return binary.LittleEndian.Uint16(data[offset:])
}

func readUint32(data []byte, offset uint32) uint32 {
	return binary.LittleEndian.Uint32(data[offset:])
}

func getChecksumOffset(data []byte) uint32 {
	return readUint32(data, 0x3c) + 0x58
}

func computeChecksum(data []byte) (checksum uint64) {
	checksumOffset := getChecksumOffset(data)

	remainder := len(data) % 4
	data_len := len(data)
	paddedData := data
	// Ensure the data is dword-aligned
	if remainder != 0 {
		padding := 4 - remainder
		data_len += padding
		paddedData = append(data, make([]byte, padding)...)
	}

	checksum = 0
	for i := 0; i < len(data)/4; i++ {
		// The checksum bytes are not considered for the checksum
		if i == int(checksumOffset)/4 {
			continue
		}
		dword := binary.LittleEndian.Uint32(paddedData[i*4:])
		checksum += uint64(dword)
		checksum = (checksum & 0xFFFFFFFF) + (checksum >> 32)
	}
	checksum = (checksum & 0xFFFF) + (checksum >> 16)
	checksum = checksum + (checksum >> 16)
	checksum = checksum & 0xFFFF
	checksum += uint64(len(data))

	return
}

func getBytes(value uint32) []byte {
	bs := make([]byte, 4)
	binary.LittleEndian.PutUint32(bs, value)
	return bs
}

func updateChecksum(data []byte) {
	checksum := uint32(computeChecksum(data))
	bs := getBytes(checksum)
	offset := getChecksumOffset(data)
	for i := 0; i < 4; i++ {
		data[offset+uint32(i)] = bs[i]
	}
}

func readDataDirectory(data []byte, offset uint32) (result DataDirectory) {
	result.VirtualAddress = readUint32(data, offset)
	result.Size = readUint32(data, offset+4)
	return
}

func ReadPayload(data []byte) []byte {
	secOffset := getSecurityDirectoryOffset(data)
	dd := readDataDirectory(data, secOffset)

	ddEnd := dd.VirtualAddress + dd.Size
	payloadSize := readUint32(data, ddEnd-4)
	payloadStart := dd.VirtualAddress + dd.Size - 4 - payloadSize
	payload := data[payloadStart : ddEnd-4]

	return payload
}

func AddPayload(data []byte, payload []byte) []byte {
	secOffset := getSecurityDirectoryOffset(data)
	dd := readDataDirectory(data, secOffset)

	// The payload must size must be a multiple of 8
	// The end token contains 4 byte
	// Therefore, the payload should be aligned on an 8-byte boundary, minus 4

	padding := (8 - ((len(payload) + 4) % 8)) % 8
	padArray := make([]byte, padding)

	paddedPayload := append(payload, padArray...)
	paddedPayload = binary.LittleEndian.AppendUint32(paddedPayload, uint32(len(paddedPayload)))

	currentSize := dd.Size
	newSize := currentSize + uint32(len(paddedPayload))
	newSizeBytes := getBytes(newSize)

	// Sausage the payload into the data directory
	ddEnd := dd.VirtualAddress + dd.Size
	pre := data[:ddEnd]
	post := data[ddEnd:]

	result := append(append(pre, paddedPayload...), post...)

	// Overwrite the size field in the data directory
	for i := 0; i < 4; i++ {
		result[i+int(secOffset)+4] = newSizeBytes[i]
	}

	// Update the checksum
	updateChecksum(result)
	return result
}

func seqEqual(a []byte, b []byte) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func IsPeFile(data []byte) bool {
	fileHeaderOffset := readUint32(data, 0x3c)
	signature := []byte{'P', 'E', 0, 0}
	return seqEqual(data[fileHeaderOffset:fileHeaderOffset+4], signature)
}

func getSecurityDirectoryOffset(data []byte) uint32 {
	fileHeaderOffset := readUint32(data, 0x3c)
	fileHeaderOffset += 4
	// sizeOfOptionalHeader := readUint16(data, fileHeaderOffset+16)
	optionalHeaderOffset := fileHeaderOffset + 20
	magicByte := readUint16(data, optionalHeaderOffset)

	var dataDirectoryOffset uint32
	if magicByte == 0x10b {
		// PE32 format
		dataDirectoryOffset = 96
	} else {
		// PE32+ format
		dataDirectoryOffset = 112
	}
	ddSize := 8
	secIndex := IMAGE_DIRECTORY_ENTRY_SECURITY
	secOffset := optionalHeaderOffset + dataDirectoryOffset + (uint32(ddSize) * uint32(secIndex))

	return secOffset
}
