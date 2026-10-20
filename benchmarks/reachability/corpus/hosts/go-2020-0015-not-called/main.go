package main

import (
	"fmt"

	"golang.org/x/text/encoding/unicode"
)

func main() {
	fmt.Println(unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM))
}
