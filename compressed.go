package wiresharklib

import (
	"compress/gzip"
	"errors"
	"io"
	"os"
)

type CompressedFileReader struct {
	fileObj  *os.File
	gzReader *gzip.Reader
	reader   io.Reader
}

func OpenCompressedFile(filename string) (*CompressedFileReader, error) {
	fh, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	s := &CompressedFileReader{
		fileObj: fh,
	}

	s.gzReader, err = gzip.NewReader(s.fileObj)
	if err == nil {
		s.reader = s.gzReader
	} else {
		// It wasn't compressed. Need to reset the file reader
		s.gzReader = nil
		s.reader = s.fileObj
		_, err := s.fileObj.Seek(0, os.SEEK_SET)
		if err != nil {
			s.fileObj.Close()
			return nil, err
		}
	}
	return s, nil
}

func (s *CompressedFileReader) Read(p []byte) (n int, err error) {
	return s.reader.Read(p)
}

func (s *CompressedFileReader) Close() error {
	var errs error

	if s.gzReader != nil {
		err := s.gzReader.Close()
		errs = errors.Join(errs, err)
		s.gzReader = nil
	}

	if s.fileObj != nil {
		err := s.fileObj.Close()
		errs = errors.Join(errs, err)
		s.fileObj = nil
	}
	return errs
}
