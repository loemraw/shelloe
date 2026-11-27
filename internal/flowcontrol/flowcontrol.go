// Package flowcontrol passes a stream to a consumer that processes it asynchronously, such as a terminal in the browser, holding at most a few chunks there unprocessed.
package flowcontrol

import "io"

const (
	ChunkSize = 32 << 10 // the most passed to the consumer in one write
	// ChunksInFlight is how many chunks the consumer may hold before it has processed them.
	ChunksInFlight = 4
)

// Output passes a stream to the consumer, holding at most ChunksInFlight
// chunks there that the consumer hasn't processed yet.
type Output struct{ slots chan struct{} }

func New() *Output {
	return &Output{slots: make(chan struct{}, ChunksInFlight)}
}

// Copy reads r until it fails, passing each chunk of at most ChunkSize bytes
// to write. write must not keep the chunk: its buffer is reused.
func (o *Output) Copy(r io.Reader, write func(chunk []byte)) {
	buffer := make([]byte, ChunkSize)
	for {
		n, err := r.Read(buffer)
		if n > 0 {
			// Waiting for the consumer to process earlier chunks stops the reading
			// when it falls behind, so the stream's sender has to wait too.
			o.slots <- struct{}{}
			write(buffer[:n])
		}
		if err != nil {
			return
		}
	}
}

// Processed frees one chunk's slot: the consumer calls it once it has processed a chunk.
func (o *Output) Processed() {
	select {
	case <-o.slots:
	default:
	}
}
