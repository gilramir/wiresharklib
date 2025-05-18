package wiresharklib

import (
	"fmt"
	"io"
	"math"
	"time"
	"unique"

	"github.com/buger/jsonparser"
)

func GetStringHandle(t string) unique.Handle[string] {
	return unique.Make[string](t)
}

type Frame struct {
	rawJson []byte

	Number       uint64
	Time         time.Time
	TimeRelative time.Duration
	TimeEpoch    float64
	Len          uint64

	Layers []*ProtoNode
}

func (s *Frame) Dump(w io.Writer) {
	fmt.Fprintf(w, "Number: %d\n", s.Number)
	fmt.Fprintf(w, "Time: %s\n", s.Time.Format(time.RFC3339Nano))
	fmt.Fprintf(w, "TimeRelative: %s\n", s.TimeRelative.String())
	fmt.Fprintf(w, "Len: %d\n", s.Len)

	for _, layer := range s.Layers {
		layer.Dump(w)
	}
}

var (
	FrameHandle             unique.Handle[string]
	FrameTimeEpochHandle    unique.Handle[string]
	FrameTimeRelativeHandle unique.Handle[string]
	FrameNumberHandle       unique.Handle[string]
	FrameLenHandle          unique.Handle[string]
)

func init() {
	FrameHandle = unique.Make[string]("frame")
	FrameTimeEpochHandle = unique.Make[string]("frame.time_epoch")
	FrameTimeRelativeHandle = unique.Make[string]("frame.time_relative")
	FrameNumberHandle = unique.Make[string]("frame.number")
	FrameLenHandle = unique.Make[string]("frame.len")
}

func (s *ProtoNode) Name() string {
	return s.nameHandle.Value()
}

func NewFrameFromBytes(rawJson []byte) (*Frame, error) {
	privateCopy := make([]byte, len(rawJson))
	copy(privateCopy, rawJson)

	s := &Frame{
		rawJson: privateCopy,
	}

	value, dataType, _, err := jsonparser.Get(privateCopy, "_source", "layers")
	if err != nil {
		return nil, err
	}
	if dataType != jsonparser.Object {
		return nil, fmt.Errorf("Expected _source/layers to be an Object, not %v", dataType)
	}

	err = s.parseLayers(value)
	if err != nil {
		return nil, err
	}

	// We get some special fields from the "frame" layer
	if len(s.Layers) > 0 && s.Layers[0].nameHandle == FrameHandle {
		// Loop on the fields in the "frame" layer, picking out the
		// ones we want. Stop when we find all that we are looking for

		var bitTimeEpoch = 0x1
		var bitTimeRelative = 0x2
		var bitNumber = 0x4
		var bitLen = 0x8

		var need int
		need = bitTimeEpoch | bitTimeRelative | bitNumber | bitLen

		frameLayer := s.Layers[0]
		for _, child := range frameLayer.Children {
			switch child.nameHandle {
			case FrameTimeEpochHandle:
				// clear the need bit
				need ^= bitTimeEpoch

				v, err := child.GetFloat64Value()
				if err != nil {
					return nil, err
				}
				s.TimeEpoch = v
				epoch_s_float := math.Floor(v)
				epoch_s := int64(math.Floor(v))
				epoch_ns := int64(math.Floor((v - epoch_s_float) * 1_000_000_000))
				s.Time = time.Unix(epoch_s, epoch_ns)

			case FrameTimeRelativeHandle:
				// clear the need bit
				need ^= bitTimeRelative

				durationString := string(child.Value) + "s"
				duration, err := time.ParseDuration(durationString)
				if err != nil {
					return nil, err
				}
				s.TimeRelative = duration

			case FrameNumberHandle:
				// clear the need bit
				need ^= bitNumber

				v, err := child.GetUint64Value(10)
				if err != nil {
					return nil, err
				}
				s.Number = v

			case FrameLenHandle:
				// clear the need bit
				need ^= bitLen

				v, err := child.GetUint64Value(10)
				if err != nil {
					return nil, err
				}
				s.Len = v

			default:
				// no-op
			}
			// Done?
			if need == 0x0 {
				break
			}
		}
	}

	return s, nil
}

// var handler func([]byte, []byte, jsonparser.ValueType, int) error
func (s *Frame) parseLayers(jsonBytes []byte) error {
	handler := func(key []byte, value []byte, dataType jsonparser.ValueType, offset int) error {
		//		fmt.Printf("layer key=%s offset=%d body=%s\n", string(key), offset, string(value))
		protoNodes, err := s.parseProtoTreeBody(value)
		if err != nil {
			return err
		}
		layerNode := &ProtoNode{
			nameHandle: GetStringHandle(string(key)),
			Children:   protoNodes,
		}
		s.Layers = append(s.Layers, layerNode)
		return nil
	}
	return jsonparser.ObjectEach(jsonBytes, handler)
}

func (s *Frame) parseProtoTreeBody(jsonBytes []byte) ([]*ProtoNode, error) {
	nodes := make([]*ProtoNode, 0)

	handler := func(key []byte, value []byte, dataType jsonparser.ValueType, offset int) error {
		//		fmt.Printf("treeBody key=%s offset=%d body=%s\n", string(key), offset, string(value))
		switch dataType {
		case jsonparser.String:
			stringNode := &ProtoNode{
				nameHandle: GetStringHandle(string(key)),
				Value:      value,
			}
			nodes = append(nodes, stringNode)

		case jsonparser.Object:
			// Recurse
			childNodes, err := s.parseProtoTreeBody(value)
			if err != nil {
				return err
			}
			treeNode := &ProtoNode{
				nameHandle: GetStringHandle(string(key)),
				Children:   childNodes,
			}
			nodes = append(nodes, treeNode)
		default:
			return fmt.Errorf("Unexpected value type key=%s value=%s", string(key),
				string(value))
		}
		return nil
	}

	err := jsonparser.ObjectEach(jsonBytes, handler)
	if err != nil {
		return nil, err
	}
	return nodes, nil
}
