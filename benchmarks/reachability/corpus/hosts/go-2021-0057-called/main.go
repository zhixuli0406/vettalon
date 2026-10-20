package main

import (
	"fmt"

	"github.com/buger/jsonparser"
)

func main() {
	value, err := jsonparser.GetString([]byte(`{"a":"b"}`), "a")
	fmt.Println(value, err)
}
