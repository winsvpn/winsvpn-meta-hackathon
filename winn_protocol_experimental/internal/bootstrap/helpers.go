package bootstrap

import (
	"context"
	"net/http"
	"strconv"
	"time"
)

func contextWithTimeout(request *http.Request, timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(request.Context(), timeout)
}

func uintToString(value uint64) string {
	return strconv.FormatUint(value, 10)
}
