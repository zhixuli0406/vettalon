package main

import (
	"fmt"
	"io"

	"github.com/sirupsen/logrus"
)

func main() {
	logger := logrus.New()
	logger.Out = io.Discard
	logger.Info("fixture")
	fmt.Println("logged")
}
