package main

import (
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

	parser, err := wiresharklib.NewJsonExportParser("../example.json")
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
