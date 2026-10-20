package main

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

func main() {
	out, err := yaml.Marshal(map[string]int{"a": 1})
	fmt.Println(len(out), err)
}
