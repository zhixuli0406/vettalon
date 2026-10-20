package main

import (
	"bytes"
	"fmt"

	"github.com/yuin/goldmark"
)

func main() {
	var out bytes.Buffer
	err := goldmark.Convert([]byte("plain fixture text"), &out)
	fmt.Println(out.Len() > 0, err)
}
