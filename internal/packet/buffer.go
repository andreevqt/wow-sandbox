package packet

import (
	"encoding/binary"
	"io"
	"math"
)

// Writer accumulates little-endian encoded bytes.
type Writer struct{ b []byte }

func NewWriter() *Writer { return &Writer{} }

func (w *Writer) U8(v uint8)   { w.b = append(w.b, v) }
func (w *Writer) U16(v uint16) { w.b = binary.LittleEndian.AppendUint16(w.b, v) }
func (w *Writer) U32(v uint32) { w.b = binary.LittleEndian.AppendUint32(w.b, v) }
func (w *Writer) U64(v uint64) { w.b = binary.LittleEndian.AppendUint64(w.b, v) }
func (w *Writer) F32(v float32) {
	w.b = binary.LittleEndian.AppendUint32(w.b, math.Float32bits(v))
}
func (w *Writer) Raw(p []byte) { w.b = append(w.b, p...) }
func (w *Writer) CString(s string) {
	w.b = append(w.b, []byte(s)...)
	w.b = append(w.b, 0)
}
func (w *Writer) Bytes() []byte { return w.b }

// Reader consumes little-endian encoded bytes.
type Reader struct {
	b   []byte
	pos int
}

func NewReader(b []byte) *Reader { return &Reader{b: b} }

func (r *Reader) U8() (uint8, error) {
	if r.pos+1 > len(r.b) {
		return 0, io.ErrUnexpectedEOF
	}
	v := r.b[r.pos]
	r.pos++
	return v, nil
}

func (r *Reader) U16() (uint16, error) {
	if r.pos+2 > len(r.b) {
		return 0, io.ErrUnexpectedEOF
	}
	v := binary.LittleEndian.Uint16(r.b[r.pos:])
	r.pos += 2
	return v, nil
}

func (r *Reader) U32() (uint32, error) {
	if r.pos+4 > len(r.b) {
		return 0, io.ErrUnexpectedEOF
	}
	v := binary.LittleEndian.Uint32(r.b[r.pos:])
	r.pos += 4
	return v, nil
}

func (r *Reader) Take(n int) ([]byte, error) {
	if r.pos+n > len(r.b) {
		return nil, io.ErrUnexpectedEOF
	}
	v := make([]byte, n)
	copy(v, r.b[r.pos:r.pos+n])
	r.pos += n
	return v, nil
}
