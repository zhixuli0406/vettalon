package main

import (
	"fmt"

	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
)

func main() {
	decoder := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder()
	out, _, err := transform.String(decoder, "h\x00i\x00")
	fmt.Println(out, err)
}
