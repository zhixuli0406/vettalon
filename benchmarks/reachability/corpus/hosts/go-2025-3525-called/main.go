package main

import (
	"fmt"

	"github.com/expr-lang/expr"
)

func main() {
	program, err := expr.Compile("1 + 2")
	if err != nil {
		panic(err)
	}
	out, err := expr.Run(program, nil)
	fmt.Println(out, err)
}
