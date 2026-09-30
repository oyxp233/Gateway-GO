package httprouter

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// countReadBody 记录请求体实际被读走的字节数。
type countReadBody struct {
	r io.Reader
	n int64
}

func (c *countReadBody) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func (c *countReadBody) Close() error { return nil }

func makeReq(method, body string) (*http.Request, *countReadBody) {
	cb := &countReadBody{r: bytes.NewBufferString(body)}
	r := httptest.NewRequest(method, "/probe", nil)
	r.Body = cb
	r.ContentLength = int64(len(body))
	return r, cb
}

// 拒绝响应（4xx）必须把请求体读掉 —— 这正是 RST 的成因。
func TestWithBodyDrainReadsBodyOnRejection(t *testing.T) {
	h := withBodyDrain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized) // 刻意不读 body
	}))
	r, cb := makeReq(http.MethodPost, "0123456789")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	if cb.n != 10 {
		t.Fatalf("4xx 响应应读掉请求体：期望 10 字节，实际 %d", cb.n)
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("状态码应原样透传：期望 401，实际 %d", rec.Code)
	}
}

// 404 走的是 mux/标准库的 NotFound，同样要 drain。
func TestWithBodyDrainReadsBodyOnNotFound(t *testing.T) {
	h := withBodyDrain(http.NotFoundHandler())
	r, cb := makeReq(http.MethodPost, "abcdef")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	if cb.n != 6 {
		t.Fatalf("404 响应应读掉请求体：期望 6 字节，实际 %d", cb.n)
	}
	if rec.Code != http.StatusNotFound {
		t.Fatalf("期望 404，实际 %d", rec.Code)
	}
}

// 成功响应不读：热路径保持零开销。
func TestWithBodyDrainSkipsBodyOnSuccess(t *testing.T) {
	h := withBodyDrain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	}))
	r, cb := makeReq(http.MethodPost, "0123456789")
	h.ServeHTTP(httptest.NewRecorder(), r)

	if cb.n != 0 {
		t.Fatalf("成功响应不该读请求体：实际读了 %d 字节", cb.n)
	}
}

// 3xx 也不算拒绝，不读。
func TestWithBodyDrainSkipsBodyOnRedirect(t *testing.T) {
	h := withBodyDrain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusFound)
	}))
	r, cb := makeReq(http.MethodPost, "0123456789")
	h.ServeHTTP(httptest.NewRecorder(), r)

	if cb.n != 0 {
		t.Fatalf("3xx 不该读请求体：实际读了 %d 字节", cb.n)
	}
}

// handler 自己读完 body 后再返回 4xx：drain 是幂等空操作，不会重复读、不会 panic。
func TestWithBodyDrainAfterHandlerAlreadyRead(t *testing.T) {
	var got string
	h := withBodyDrain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = string(b)
		w.WriteHeader(http.StatusBadRequest)
	}))
	r, cb := makeReq(http.MethodPost, "abcdef")
	h.ServeHTTP(httptest.NewRecorder(), r)

	if got != "abcdef" {
		t.Fatalf("handler 应拿到完整 body：实际 %q", got)
	}
	if cb.n != 6 {
		t.Fatalf("body 只应被读一次：期望 6 字节，实际 %d", cb.n)
	}
}

// 超大 body 只读到上限，不做无上限读取。
func TestWithBodyDrainCapsReadSize(t *testing.T) {
	body := bytes.Repeat([]byte("x"), maxDrainBodyBytes+5000)
	h := withBodyDrain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	r, cb := makeReq(http.MethodPost, string(body))
	h.ServeHTTP(httptest.NewRecorder(), r)

	if cb.n != maxDrainBodyBytes {
		t.Fatalf("应恰好读到上限 %d：实际 %d", maxDrainBodyBytes, cb.n)
	}
}

// GET/HEAD 无 body：不包装，直接透传。
func TestWithBodyDrainSkipsEmptyBody(t *testing.T) {
	called := false
	h := withBodyDrain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	r := httptest.NewRequest(http.MethodGet, "/probe", nil)
	r.Body = http.NoBody
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	if !called || rec.Code != http.StatusOK {
		t.Fatalf("GET 应正常透传：called=%v code=%d", called, rec.Code)
	}
}

// 连续两次写（显式 4xx 后 Write）：drain 只执行一次。
func TestDrainIsIdempotent(t *testing.T) {
	rec := httptest.NewRecorder()
	r, body := makeReq(http.MethodPost, "0123")
	dw := &drainingResponseWriter{ResponseWriter: rec, req: r}
	dw.WriteHeader(http.StatusForbidden)
	_, _ = dw.Write([]byte("x"))
	_, _ = dw.Write([]byte("y"))

	if body.n != 4 {
		t.Fatalf("drain 应只读一次：期望 4 字节，实际 %d", body.n)
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("期望 403，实际 %d", rec.Code)
	}
}
