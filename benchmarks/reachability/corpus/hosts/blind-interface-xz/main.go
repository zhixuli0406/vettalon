package main

import (
	"bytes"
	"fmt"
	"io"

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
	// io.ReadAll calls Read through the io.Reader interface.
	var reader io.Reader
	reader, err := xz.NewReader(compressed())
	if err != nil {
		panic(err)
	}
	data, err := io.ReadAll(reader)
	fmt.Println(len(data), err)
}
