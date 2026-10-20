package main

import (
	"fmt"

	"github.com/Masterminds/goutils"
)

func main() {
	value, err := goutils.RandomAlphaNumeric(8)
	fmt.Println(len(value), err)
}
