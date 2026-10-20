package main

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v2"
)

func main() {
	// The decoder is selected from a map of function values at run time.
	decoders := map[string]func([]byte, interface{}) error{
		"yaml": yaml.Unmarshal,
		"none": func([]byte, interface{}) error { return nil },
	}
	var value map[string]int
	err := decoders[strings.ToLower("YAML")]([]byte("a: 1\n"), &value)
	fmt.Println(value["a"], err)
}
