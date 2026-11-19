package proxy

import (
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

// TestClassifyReadEnd 锁定断链原因分类——「挂机掉线」排查全靠这几列区分
// 客户端自己断、代理空闲超时、本端主动关闭。任何一条回归都会让日志失去诊断价值。
func TestClassifyReadEnd(t *testing.T) {
	idle := 30 * time.Minute

	cases := []struct {
		name  string
		err   error
		cause string
	}{
		{"nil -> zero-read", nil, "zero-read"},
		{"shutdown", errShutdown, "shutdown"},
		{"deadline -> idle-timeout", os.ErrDeadlineExceeded, "idle-timeout"},
		{"net.ErrClosed -> local-close", net.ErrClosed, "local-close"},
		{"eof", io.EOF, "eof"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyReadEnd(tc.err, idle)
			if got.cause != tc.cause {
				t.Fatalf("classifyReadEnd(%v).cause = %q, want %q", tc.err, got.cause, tc.cause)
			}
		})
	}

	// net.Error.Timeout() 但非 os.ErrDeadlineExceeded（某些平台 ReadDeadline 返回这种）
	t.Run("wrapped net timeout -> idle-timeout", func(t *testing.T) {
		got := classifyReadEnd(&net.OpError{Op: "read", Err: &timeoutErr{}}, idle)
		if got.cause != "idle-timeout" {
			t.Fatalf("cause = %q, want idle-timeout", got.cause)
		}
	})

	// 普通错误归 read-error，且保留 detail 原文
	t.Run("arbitrary -> read-error with detail", func(t *testing.T) {
		got := classifyReadEnd(errors.New("connection reset by peer"), idle)
		if got.cause != "read-error" || got.detail != "connection reset by peer" {
			t.Fatalf("got %+v, want read-error with detail", got)
		}
	})

	// idle-timeout 的 detail 应带秒数，便于一眼确认是 1800s 那个开关
	t.Run("idle-timeout detail carries seconds", func(t *testing.T) {
		got := classifyReadEnd(os.ErrDeadlineExceeded, idle)
		if got.detail != "1800s无数据" {
			t.Fatalf("detail = %q, want %q", got.detail, "1800s无数据")
		}
	})
}

// timeoutErr 是一个只实现 net.Error.Timeout() 的最小桩。
type timeoutErr struct{}

func (*timeoutErr) Error() string   { return "i/o timeout" }
func (*timeoutErr) Timeout() bool   { return true }
func (*timeoutErr) Temporary() bool { return true }

// TestCopyEndString 锁定日志里的可读格式。
func TestCopyEndString(t *testing.T) {
	if got := (copyEnd{cause: "eof"}).String(); got != "eof" {
		t.Fatalf("String() = %q, want eof", got)
	}
	if got := (copyEnd{cause: "read-error", detail: "reset"}).String(); got != "read-error(reset)" {
		t.Fatalf("String() = %q, want read-error(reset)", got)
	}
}
