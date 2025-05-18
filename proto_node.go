package wiresharklib

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"unique"
	"unsafe"
)

type ProtoNode struct {
	nameHandle unique.Handle[string]
	Value      []byte
	Children   []*ProtoNode
}

func (s *ProtoNode) Dump(w io.Writer) {
	s.dump(w, 0)
}

func (s *ProtoNode) dump(w io.Writer, indent int) {
	spaces := strings.Repeat("  ", indent)

	if len(s.Value) > 0 {
		fmt.Fprintf(w, "%s%s: %s\n", spaces, s.nameHandle.Value(), string(s.Value))
	} else if len(s.Children) > 0 {
		fmt.Fprintf(w, "%s%s:\n", spaces, s.nameHandle.Value())
	} else {
		// This should never happen
		fmt.Fprintf(w, "%s%s", spaces, s.nameHandle.Value())
	}
	for _, child := range s.Children {
		child.dump(w, indent+1)
	}
}

func (s *ProtoNode) GetFloat64Value() (v float64, err error) {
	var zero float64

	// Use an unsafe string because it's faster, and we only need it for
	// this strconv
	v, err = strconv.ParseFloat(unsafe.String(&s.Value[0], len(s.Value)), 64)
	if err != nil {
		return zero, err
	}
	return v, nil
}

func (s *ProtoNode) GetUint64Value(base int) (v uint64, err error) {
	var zero uint64

	// Use an unsafe string because it's faster, and we only need it for
	// this strconv
	v, err = strconv.ParseUint(unsafe.String(&s.Value[0], len(s.Value)), base, 64)
	if err != nil {
		return zero, err
	}
	return v, nil
}

/*
// Find the first
func (s *ProtoNode) GetFirstFieldFloat(handle unique.Handle[string]) (v float64, has bool, err error) {
	var zero float64

	n, has := s.FindFirstField(handle)
	if !has {
		return zero, false, nil
	}

	// Use an unsafe string because it's faster, and we only need it for
	// this strconv
	v, err = strconv.ParseFloat(unsafe.String(&n.Value[0], len(n.Value)), 64)
	if err != nil {
		return zero, false, err
	}
	//	fmt.Printf("GetFirstFieldFloat %s -> %f\n", string(n.Value), v)
	return v, true, nil
}

func (s *ProtoNode) FindFirstField(needleHandle unique.Handle[string]) (n *ProtoNode, has bool) {
	for _, n = range s.Children {
		if n.nameHandle == needleHandle {
			return n, true
		}
	}
	return nil, false
}
*/
