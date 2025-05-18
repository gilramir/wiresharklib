package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"

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

	var filename string
	var max_token_size int

	if len(os.Args) < 2 {
		return errors.New("Give the name of the file to read")
	}
	filename = os.Args[1]
	max_token_size = 65536
	if len(os.Args) >= 3 {
		v, err := strconv.ParseInt(os.Args[2], 10, 64)
		if err != nil {
			return err
		}
		max_token_size = int(v)
	}

	//	fmt.Printf("Using max_token_size %d\n", max_token_size)
	parser, err := wiresharklib.NewJsonExportParser(filename,
		wiresharklib.SetMaxTokenSize(max_token_size),
	)
	if err != nil {
		return err
	}

	for parser.NextFrame() {
		frame := parser.Frame()
		fmt.Printf("Got frame:\n")
		frame.Dump(os.Stdout)
		fmt.Println()
	}

	err = parser.Err()
	if err != nil {
		return err
	}

	return nil

}
