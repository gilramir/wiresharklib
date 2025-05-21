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

**NOTE** - the code is fast, but at this point, a little "special". It expects to
parse a JSON file exactly that came from Wireshark, without reformatting. The
code relies on the exact indentation of curly braces that Wireshark produces,
in order to quickly find the frame boundaries.  As long as you aren't
reformatting the Wireshark you will have no problems. If for some reaosn you
are reformatting the JSON file, this library won't work for you.

The library can handle JSON files with new-line line endings, as well as
carriage-return, new-line endings. So you can read a file that was produced by
Wireshark on Windows, or Unix or Mac.

Also, this library can transparently read gzip-compressed files. You do not
need to decompress them before parsing them.

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

## String Handles

The JsonExportParser API makes use of string Handles as produced by Go's
[unique package](https://pkg.go.dev/unique) to provide fast searching for
protocols and fields (ProtoNode objects). Typically you will be searching many
frames for the same protocol or field name, so you will want to create the
handle one time, and use it over and over again. For example:

```
    ethHandle := unique.Make[string]("eth")

	for parser.NextFrame() {
		frame := parser.Frame()
        ethLayer, has := frame.FindLayer(ethHandle)
        if has {
           // Do something
        }
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
func (s *Frame) FindLayer(layerHandle unique.Handle[string]) (n *ProtoNode, has bool)
```

Find the first ProtoNode layer whose name matches the handle.

## ProtoNode

A ProtoNode corresponds to one node in the protocol dissection tree in the
Wireshark UI. It may be "protocol" node, or a "field" node, or a protocol's
"sub-field", which will just expand the details of a field into smaller chunks.

```
type ProtoNode struct {
	nameHandle unique.Handle[string]
	Value      []byte
	Children   []*ProtoNode
}
```

It has a name (retrieved via the Name() method), and []byte
Value, which might be empty. It may have children ProtoNodes too. The children
correspond to the child branches of the dissection protocol tree in the
Wireshark UI.

Methods:

```
func (s *ProtoNode) Name() string
```
Get the name of the ProtoNode. Internally the ProtoNode has a unique.Handle for
its name. This Name method simply calls the unique.Handle.Value() method.

```
func (s *ProtoNode) Dump(w io.Writer)
```
To see the representation of the this ProtoNode, and all if its children, if it
has any.

These methods let you retreive the Value of the ProtoNode as different types.

```
func (s *ProtoNode) GetFloat64Value() (v float64, err error)
func (s *ProtoNode) GetStringValue() (v string)
func (s *ProtoNode) GetUint64Value(base int) (v uint64, err error)
```

To search for other ProtoNodes, use the following methods.

```
func (s *ProtoNode) FindField(needleHandle unique.Handle[string]) (n *ProtoNode, has bool)
```
Returns the first occurence of a direct child of this ProtoNode. This function
does not recurse into the grandchildren.


```
func (s *ProtoNode) FindFieldHasPrefix(prefix string) (n *ProtoNode, has bool)
```
Returns the first occurence of a direct child of this ProtoNode whose name
starts with the given string.
This function does not recurse into the grandchildren.
Note that this function takes a string argument, not a unique.Handle argument.

