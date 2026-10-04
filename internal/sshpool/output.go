package sshpool

import (
	"bytes"
	"io"
	"strings"
	"sync"
	"unicode/utf8"
)

const truncationMarker = "\n… [truncated] …\n"

// headTailBuffer keeps bounded output while counting every byte received.
type headTailBuffer struct {
	mu      sync.Mutex
	limit   int
	total   int64
	head    []byte
	tail    []byte
	tailPos int
}

func newHeadTailBuffer(limit int) *headTailBuffer {
	return &headTailBuffer{limit: limit}
}

func (b *headTailBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	b.total += int64(n)
	headLimit := (b.limit + 1) / 2
	if remaining := headLimit - len(b.head); remaining > 0 {
		if remaining > len(p) {
			remaining = len(p)
		}
		b.head = append(b.head, p[:remaining]...)
		p = p[remaining:]
	}
	tailLimit := b.limit - headLimit
	if tailLimit == 0 {
		return n, nil
	}
	if len(p) >= tailLimit {
		b.tail = append(b.tail[:0], p[len(p)-tailLimit:]...)
		b.tailPos = 0
		return n, nil
	}
	for _, c := range p {
		if len(b.tail) < tailLimit {
			b.tail = append(b.tail, c)
		} else {
			b.tail[b.tailPos] = c
			b.tailPos = (b.tailPos + 1) % tailLimit
		}
	}
	return n, nil
}

func (b *headTailBuffer) snapshot() ([]byte, int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	p := append([]byte(nil), b.head...)
	p = append(p, b.tail[b.tailPos:]...)
	p = append(p, b.tail[:b.tailPos]...)
	return p, b.total
}

func safePrefix(s string, limit int) string {
	if limit <= 0 {
		return ""
	}
	if len(s) <= limit {
		return s
	}
	for limit > 0 && !utf8.RuneStart(s[limit]) {
		limit--
	}
	return s[:limit]
}

func safeSuffix(s string, limit int) string {
	if limit <= 0 {
		return ""
	}
	if len(s) <= limit {
		return s
	}
	start := len(s) - limit
	for start < len(s) && !utf8.RuneStart(s[start]) {
		start++
	}
	return s[start:]
}

func boundedOutput(p []byte, original int64, budget int) (string, bool) {
	s := strings.ToValidUTF8(string(p), "�")
	truncated := original > int64(len(p)) || len(s) > budget
	if !truncated {
		return s, false
	}
	if budget <= 0 {
		return "", true
	}
	marker := ""
	if budget >= len(truncationMarker)+8 {
		marker = truncationMarker
	}
	remaining := budget - len(marker)
	return safePrefix(s, (remaining+1)/2) + marker + safeSuffix(s, remaining/2), true
}

func renderOutput(stdout, stderr *headTailBuffer, limit int) (out, errOut string, truncated bool) {
	o, on := stdout.snapshot()
	e, en := stderr.snapshot()
	// Allocate the combined budget fairly, allowing a short stream to fit whole.
	ob, eb := limit, 0
	if en > 0 {
		if on == 0 {
			ob, eb = 0, limit
		} else {
			eb = limit / 2
			ob = limit - eb
			if on < int64(ob) {
				ob, eb = int(on), limit-int(on)
			}
			if en < int64(eb) {
				eb, ob = int(en), limit-int(en)
			}
		}
	}
	out, ot := boundedOutput(o, on, ob)
	errOut, et := boundedOutput(e, en, eb)
	return out, errOut, ot || et
}

// redactingWriter recognizes secrets even when they span SSH packet boundaries.
type redactingWriter struct {
	target  io.Writer
	secret  []byte
	pending []byte
	total   int64
}

func (w *redactingWriter) Write(p []byte) (int, error) {
	n := len(p)
	w.total += int64(n)
	if len(w.secret) == 0 {
		_, err := w.target.Write(p)
		return n, err
	}
	data := append(w.pending, p...)
	w.pending = nil
	var output []byte
	for {
		i := bytes.Index(data, w.secret)
		if i < 0 {
			break
		}
		output = append(output, data[:i]...)
		output = append(output, "[REDACTED]"...)
		data = data[i+len(w.secret):]
	}
	keep := len(w.secret) - 1
	if keep > len(data) {
		keep = len(data)
	}
	output = append(output, data[:len(data)-keep]...)
	w.pending = append(w.pending, data[len(data)-keep:]...)
	_, err := w.target.Write(output)
	return n, err
}

func (w *redactingWriter) flush() error {
	_, err := w.target.Write(w.pending)
	w.pending = nil
	return err
}

type redactingReader struct {
	source io.Reader
	buffer bytes.Buffer
	writer redactingWriter
	err    error
}

func newRedactingReader(source io.Reader, secret string) io.Reader {
	if secret == "" {
		return source
	}
	r := &redactingReader{source: source}
	r.writer = redactingWriter{target: &r.buffer, secret: []byte(secret)}
	return r
}

func (r *redactingReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for r.buffer.Len() == 0 && r.err == nil {
		var chunk [32768]byte
		n, err := r.source.Read(chunk[:])
		if n > 0 {
			_, _ = r.writer.Write(chunk[:n])
		}
		if err != nil {
			r.err = err
			_ = r.writer.flush()
		}
	}
	if r.buffer.Len() > 0 {
		return r.buffer.Read(p)
	}
	return 0, r.err
}
