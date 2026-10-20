package main

import (
	"fmt"

	"github.com/tidwall/gjson"
)

func main() {
	fmt.Println(gjson.Valid(`{"a":{"b":1}}`))
}
