package wiresharklib

import (
	"bufio"
	"bytes"
	"io"
)

type JsonExportParser struct {
	fileReader io.Reader
	scanner    *bufio.Scanner
	frameChan  chan *Frame
	buffer     []byte

	frame *Frame
	err   error
}

type JsonExportParserOption func(s *JsonExportParser) error

func SetMaxTokenSize(size int) JsonExportParserOption {
	return func(s *JsonExportParser) error {
		s.buffer = make([]byte, 65536, size)
		s.scanner.Buffer(s.buffer, size-1)
		return nil
	}
}

func NewJsonExportParser(filename string, opts ...JsonExportParserOption) (*JsonExportParser, error) {
	file, err := OpenCompressedFile(filename)
	if err != nil {
		return nil, err
	}
	scanner := bufio.NewScanner(file)
	scanner.Split(frameSplitFunc)

	s := &JsonExportParser{
		fileReader: file,
		scanner:    scanner,
		frameChan:  make(chan *Frame),
	}

	for _, opt := range opts {
		err = opt(s)
		if err != nil {
			return nil, err
		}
	}

	go s.readFrames()
	return s, nil
}

func frameSplitFunc(data []byte, atEOF bool) (advance int, token []byte, err error) {
	var i int
	var w int

	if atEOF {
		w = 3
		i = bytes.Index(data, []byte("\n  }"))
		err = bufio.ErrFinalToken
	} else {
		w = 4
		i = bytes.Index(data, []byte("\n  },"))
		err = nil
	}

	if i == -1 {
		return 0, nil, nil
	}

	start := bytes.Index(data, []byte("  {\n"))
	if start == -1 {
		// Maybe this file was produced on Windows
		start = bytes.Index(data, []byte("  {\r\n"))
	}

	if start == -1 {
		// An error in the input occurred
		return 0, nil, bufio.ErrFinalToken
	} else {
		return i + w, data[start : i+3], err
	}
}

func (s *JsonExportParser) NextFrame() bool {
	select {
	case frame, ok := <-s.frameChan:
		if !ok {
			return false
		}
		s.frame = frame
		return true
	}
}

func (s *JsonExportParser) Frame() *Frame {
	return s.frame
}

func (s *JsonExportParser) Cancel() {
}

func (s *JsonExportParser) Err() error {
	return s.err
}

func (s *JsonExportParser) readFrames() {
	defer close(s.frameChan)

	for s.scanner.Scan() {
		frameBytes := s.scanner.Bytes()
		//		fmt.Printf("Token: %s\n", string(frameBytes))

		frame, err := NewFrameFromBytes(frameBytes)
		if err != nil {
			// XXX - need to stop goroutine
			s.err = err
			return
		}

		s.frameChan <- frame
	}

	s.err = s.scanner.Err()
}
