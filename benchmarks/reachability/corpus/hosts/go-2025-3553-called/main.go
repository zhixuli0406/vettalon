package main

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

func main() {
	claims := jwt.MapClaims{}
	_, parts, err := jwt.NewParser().ParseUnverified("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJmaXh0dXJlIn0.c2lnbmF0dXJl", claims) // gitleaks:allow (unsigned fixture token)
	fmt.Println(len(parts), claims["sub"], err)
}
