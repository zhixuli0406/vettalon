package main

import (
	"fmt"

	"github.com/buger/jsonparser"
)

func main() {
	value, err := jsonparser.ParseBoolean([]byte("true"))
	fmt.Println(value, err)
}
