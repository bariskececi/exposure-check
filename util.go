package main

import (
	"context"
	"io"
	"os"
	"time"
)

var ioStderr io.Writer = os.Stderr

func ctxTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}
