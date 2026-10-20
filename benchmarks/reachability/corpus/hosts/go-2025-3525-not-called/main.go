package main

import (
	"fmt"

	"github.com/expr-lang/expr/ast"
)

func main() {
	node := &ast.IntegerNode{Value: 3}
	fmt.Println(node.Value)
}
