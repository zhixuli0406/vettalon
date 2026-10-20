package main

import (
	"fmt"
	"io"

	"github.com/sirupsen/logrus"
)

func main() {
	logger := logrus.New()
	logger.Out = io.Discard
	writer := logger.Writer()
	_, err := writer.Write([]byte("fixture\n"))
	fmt.Println(err, writer.Close())
}
