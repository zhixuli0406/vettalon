package main

import (
	"fmt"
	"reflect"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
)

func main() {
	// The method name is assembled at run time; no static call site names it.
	name := strings.Join([]string{"Verify", "Audience"}, "")
	method := reflect.ValueOf(jwt.MapClaims{"aud": "service"}).MethodByName(name)
	out := method.Call([]reflect.Value{reflect.ValueOf("service"), reflect.ValueOf(true)})
	fmt.Println(out[0].Bool())
}
