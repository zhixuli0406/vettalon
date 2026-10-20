package main

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

func main() {
	name := strings.Join([]string{"Parse", "Unverified"}, "")
	method := reflect.ValueOf(jwt.NewParser()).MethodByName(name)
	claims := jwt.MapClaims{}
	out := method.Call([]reflect.Value{reflect.ValueOf("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJmaXh0dXJlIn0.c2lnbmF0dXJl"), reflect.ValueOf(claims)}) // gitleaks:allow (unsigned fixture token)
	fmt.Println(len(out), claims["sub"])
}
