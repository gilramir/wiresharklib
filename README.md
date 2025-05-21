Wiresharklib is a Golang module with one purpose at the moment.
It parses the exported JSON dissection that Wireshark produces.

The exported JSON is troublesome to parse with normal libraries for two
reasons.

First, the JSON maps often have duplicate keys. This is because Wireshark
simply converts the protocol tree into a JSON map, and the protocol tree
has lists of nodes which can have duplicate names.
The JSON RFC-8259 only states that JSON objects SHOULD have unique
keys, but doesn't require it. Thus, Wireshark's JSON is legal.

Second, the JSON files can be very large enough that you don't want to, or
can't, parse the entire file into memory at once. Instead, a frame-by-frame
approach is ideal for reading these Wireshark JSON files.

# Usage

Import this module

```
import "github.com/gilramir/wiresharklib"
```

Create a JsonExportParser for the file you want to parse. The file can be
gzip-compressed, and this module will decompress it as it reads it,
automatically.

```
	parser, err := wiresharklib.NewJsonExportParser(filename)
```

Sometimes the frames you read are very large, because they can contain
reconstructed TCP streams. You will hit the 64 KB "token size limit" in the
code. You can override this with any value you want. For example:

```
	parser, err := wiresharklib.NewJsonExportParser(filename,
		wiresharklib.SetMaxTokenSize(10000000)
)
```

You inspect each frame one at at time, using NextFrame() in a loop to get a
Frame object.
After the loop is finished, you must call Err() to see if there was an error in
processing.

```
	for parser.NextFrame() {
		frame := parser.Frame()
		frame.Dump(os.Stdout)
		fmt.Println()
	}

	err = parser.Err()
	if err != nil {
		return err
	}
```

## Frames

Each Frame object has a few important metadata fields, and then the layers of
the protocol dissection.

```
type Frame struct {

	Number       uint64
	Time         time.Time
	TimeRelative time.Duration
	TimeEpoch    float64
	Len          uint64

	Layers []*ProtoNode
}
```

Each ProtoNode in Layers corresponds to the top-most protocols in the protocol
tree. So, typically you'll have layers like "frame", "eth", "ip", "tcp".

Frame objects have the following useful methods:

```
func (s *Frame) Dump(w io.Writer)
```
To see the metadata and complete dissection of the Frame.


```
func (s *Frame) FindLayer(layerHandle unique.Handle[string]) (n *ProtoNode, has bool) {
```

Find the first ProtoNode layer whose name matches the handle.


TBD
