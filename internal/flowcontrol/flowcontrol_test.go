package flowcontrol_test

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/loemraw/shelloe/internal/flowcontrol"
)

const (
	timeout = 5 * time.Second
	// quiet is how long a test waits to show that no more chunks come.
	quiet = 100 * time.Millisecond
)

// copyEndlessly runs o.Copy on a reader that always has more to give, and
// returns the chunks it writes. Nothing calls Processed unless the test does.
func copyEndlessly(t *testing.T, o *flowcontrol.Output) <-chan []byte {
	t.Helper()
	reader, writer := io.Pipe()
	go func() {
		for {
			if _, err := writer.Write(make([]byte, flowcontrol.ChunkSize)); err != nil {
				return
			}
		}
	}()
	chunks := make(chan []byte, 100)
	copied := make(chan struct{})
	go func() {
		defer close(copied)
		o.Copy(reader, func(chunk []byte) { chunks <- bytes.Clone(chunk) })
	}()
	t.Cleanup(func() {
		reader.CloseWithError(errors.New("the test is over"))
		o.Processed() // lets a Copy waiting for a slot reach the closed reader
		for {
			select {
			case <-copied:
				return
			case <-chunks:
			}
		}
	})
	return chunks
}

// receive waits for n chunks.
func receive(t *testing.T, chunks <-chan []byte, n int) {
	t.Helper()
	for i := range n {
		select {
		case <-chunks:
		case <-time.After(timeout):
			t.Fatalf("chunk %d of %d didn't come within %v", i+1, n, timeout)
		}
	}
}

// expectNoMore fails the test if another chunk comes within quiet.
func expectNoMore(t *testing.T, chunks <-chan []byte, after string) {
	t.Helper()
	select {
	case <-chunks:
		t.Fatalf("another chunk came %s", after)
	case <-time.After(quiet):
	}
}

func TestCopyStopsWhileTheConsumerIsBehind(t *testing.T) {
	chunks := copyEndlessly(t, flowcontrol.New())
	receive(t, chunks, flowcontrol.ChunksInFlight)
	expectNoMore(t, chunks, "though the consumer hasn't processed any")
}

func TestCopyLetsOneMoreChunkThroughForEachProcessedOne(t *testing.T) {
	o := flowcontrol.New()
	chunks := copyEndlessly(t, o)
	receive(t, chunks, flowcontrol.ChunksInFlight)
	expectNoMore(t, chunks, "though the consumer hasn't processed any")

	o.Processed()
	receive(t, chunks, 1)
	expectNoMore(t, chunks, "after the consumer processed only one")
}

func TestCopyDeliversEverythingInOrder(t *testing.T) {
	want := make([]byte, 3*flowcontrol.ChunkSize+1234)
	for i := range want {
		want[i] = byte(i * 7)
	}
	o := flowcontrol.New()
	var got bytes.Buffer
	copied := make(chan struct{})
	go func() {
		defer close(copied)
		o.Copy(bytes.NewReader(want), func(chunk []byte) {
			if len(chunk) > flowcontrol.ChunkSize {
				t.Errorf("a chunk has %d bytes, more than %d", len(chunk), flowcontrol.ChunkSize)
			}
			got.Write(chunk)
			o.Processed()
		})
	}()

	select {
	case <-copied:
	case <-time.After(timeout):
		t.Fatalf("Copy didn't return at EOF within %v", timeout)
	}
	if !bytes.Equal(got.Bytes(), want) {
		t.Errorf("Copy delivered %d bytes, want the reader's %d, in order", got.Len(), len(want))
	}
}
