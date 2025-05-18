package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/gilramir/wiresharklib"
)

func main() {
	err := run()
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func run() error {

	if len(os.Args) < 2 {
		return errors.New("Give the name of the file to read")
	}

	parser, err := wiresharklib.NewJsonExportParser(os.Args[1])
	if err != nil {
		return err
	}

	for parser.NextFrame() {
		frame := parser.Frame()
		fmt.Printf("Got frame:\n")
		frame.Dump(os.Stdout)
		fmt.Println()
	}

	return nil

}
