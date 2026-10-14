// Package safego 提供带 panic 兜底的 goroutine 启动器。
//
// 背景（2026-10-04 代码审查 G-1）：网关是**单进程**同时承载 TCP 认证、
// 游戏端口代理与全部在线会话，而 accept 之后是把连接交给一个裸跑的
// `go handleXxx(conn)`。任何一个这样的 goroutine panic，都会直接打挂
// 整个进程 ⇒ 全体在线玩家瞬间掉线。
//
// net/http 的 handler 有标准库自带的 per-connection recover
// （panic 只会关掉那一条连接、并往 stderr 打栈），但**自己 go 出去的
// goroutine 没有这层保护**，必须显式兜底。本包就是那层兜底。
package safego

import (
	"fmt"
	"runtime/debug"
)

// Logger 是最小日志接口，避免 safego 依赖具体的 logger 包
// （*logger.ConsoleLogger 天然满足）。
type Logger interface {
	Error(msg string)
}

// Go 启动一个带 recover 的 goroutine：panic 被记录后吞掉，进程继续跑。
//
// name 用于日志定位（例如 "auth.handleClient"）。
// 调用方式与原 `go fn()` 等价 —— fn 内部的 defer 仍照常执行。
// log 为 nil 时只丢弃 panic，仍然不崩溃。
func Go(log Logger, name string, fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				if log != nil {
					log.Error(fmt.Sprintf("[panic] %s: %v\n%s", name, r, debug.Stack()))
				}
			}
		}()
		fn()
	}()
}
