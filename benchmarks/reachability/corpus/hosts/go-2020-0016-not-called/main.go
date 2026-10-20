package main

import (
	"bytes"
	"fmt"

	"github.com/ulikunitz/xz"
)

func compressed() *bytes.Buffer {
	var buffer bytes.Buffer
	writer, err := xz.NewWriter(&buffer)
	if err != nil {
		panic(err)
	}
	if _, err := writer.Write([]byte("fixture")); err != nil {
		panic(err)
	}
	if err := writer.Close(); err != nil {
		panic(err)
	}
	return &buffer
}

func main() {
	fmt.Println(compressed().Len() > 0)
}
