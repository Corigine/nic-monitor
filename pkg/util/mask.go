package util

func MaskIsMaskAll(mask []byte) bool {
	if len(mask) == 0 {
		return false
	}

	for _, val := range mask {
		if val != 0xFF {
			return false
		}
	}

	return true
}

func MaskIsMaskNone(mask []byte) bool {
	for _, val := range mask {
		if val != 0 {
			return false
		}
	}

	return true
}
