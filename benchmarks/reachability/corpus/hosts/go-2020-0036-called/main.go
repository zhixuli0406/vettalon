package main

import (
	"fmt"

	"gopkg.in/yaml.v2"
)

func main() {
	var value map[string]int
	err := yaml.Unmarshal([]byte("a: 1\n"), &value)
	fmt.Println(value["a"], err)
}
