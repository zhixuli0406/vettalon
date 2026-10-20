package main

import (
	"fmt"
	_ "unsafe"

	_ "github.com/Masterminds/goutils"
)

// A pull linkname binds this body-less declaration to the dependency symbol;
// no Go call site names the vulnerable function.
//
//go:linkname randomAlphaNumeric github.com/Masterminds/goutils.RandomAlphaNumeric
func randomAlphaNumeric(count int) (string, error)

func main() {
	value, err := randomAlphaNumeric(8)
	fmt.Println(len(value), err)
}
