package main

import (
	"fmt"

	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
)

func main() {
	// Dynamic dispatch through the transform.Transformer interface value.
	var transformer transform.Transformer = unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder().Transformer
	dst := make([]byte, 16)
	n, _, err := transformer.Transform(dst, []byte("h\x00i\x00"), true)
	fmt.Println(string(dst[:n]), err)
}
