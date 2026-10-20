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
	reader, err := xz.NewReader(compressed())
	if err != nil {
		panic(err)
	}
	chunk := make([]byte, 64)
	total := 0
	for {
		n, err := reader.Read(chunk)
		total += n
		if err != nil {
			break
		}
	}
	fmt.Println(total)
}
