package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

const (
	gatewayHost = "192.168.1.202"
	gatewayPort = 8000
)

type GatewayRequest struct {
	Cmd             string  `json:"cmd"`
	Account         *string `json:"account,omitempty"`
	PasswordMd5     *string `json:"password_md5,omitempty"`
	DeviceSecret    *string `json:"device_secret,omitempty"`
	AuthKey         *string `json:"auth_key,omitempty"`
	LauncherVersion *string `json:"launcher_version,omitempty"`
}

type GatewayResponse struct {
	Cmd            string  `json:"cmd"`
	Ok             bool    `json:"ok"`
	ErrorCode      int     `json:"error_code,omitempty"`
	Message        *string `json:"message,omitempty"`
	Token          *string `json:"token,omitempty"`
	MId            *string `json:"m_id,omitempty"`
	Cera           *int64  `json:"cera,omitempty"`
	TokenCera      *int64  `json:"token_cera,omitempty"`
	HappyTokenCera *int64  `json:"happy_token_cera,omitempty"`
	DeviceSecret   *string `json:"device_secret,omitempty"`
	DeviceChanged  *bool   `json:"device_changed,omitempty"`
	Version        *string `json:"version,omitempty"`
	DownloadUrl    *string `json:"download_url,omitempty"`
}

func strPtr(s string) *string { return &s }
func int64Ptr(i int64) *int64 { return &i }

func connect() (net.Conn, error) {
	return net.DialTimeout("tcp", fmt.Sprintf("%s:%d", gatewayHost, gatewayPort), 5*time.Second)
}

func sendFrame(conn net.Conn, data []byte) error {
	if len(data) > 1024*1024 {
		return fmt.Errorf("frame too large")
	}
	buf := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(buf[:4], uint32(len(data)))
	copy(buf[4:], data)
	_, err := conn.Write(buf)
	return err
}

func readFrame(conn net.Conn) ([]byte, error) {
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	header := make([]byte, 4)
	_, err := io.ReadFull(conn, header)
	if err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(header)
	if length > 1024*1024 {
		return nil, fmt.Errorf("frame too large: %d", length)
	}
	data := make([]byte, length)
	_, err = io.ReadFull(conn, data)
	return data, err
}

func cmdLogin(account, password, deviceSecret string) {
	fmt.Printf("[TEST] 登录: %s\n", account)
	conn, err := connect()
	if err != nil {
		fmt.Printf("[ERR] 连接失败: %v\n", err)
		return
	}
	defer conn.Close()

	req := GatewayRequest{
		Cmd:             "CMD_LOGIN",
		Account:         strPtr(account),
		PasswordMd5:     strPtr(password),
		DeviceSecret:    strPtr(deviceSecret),
		LauncherVersion: strPtr("2.0.0"),
	}
	data, _ := json.Marshal(req)
	if err := sendFrame(conn, data); err != nil {
		fmt.Printf("[ERR] 发送失败: %v\n", err)
		return
	}

	respData, err := readFrame(conn)
	if err != nil {
		fmt.Printf("[ERR] 读取失败: %v\n", err)
		return
	}

	var resp GatewayResponse
	if err := json.Unmarshal(respData, &resp); err != nil {
		fmt.Printf("[ERR] 解析失败: %v\n", err)
		return
	}

	if !resp.Ok {
		fmt.Printf("[FAIL] 登录失败: code=%d msg=%v\n", resp.ErrorCode, deref(resp.Message))
		return
	}

	fmt.Printf("[OK] 登录成功!\n")
	fmt.Printf("  Token: %s\n", deref(resp.Token))
	fmt.Printf("  MId: %s\n", deref(resp.MId))
	fmt.Printf("  Cera: %d\n", int64Deref(resp.Cera))
	fmt.Printf("  DeviceSecret: %s\n", deref(resp.DeviceSecret))
	fmt.Printf("  DeviceChanged: %v\n", boolDeref(resp.DeviceChanged))
}

func cmdVersion() {
	fmt.Println("[TEST] 检查版本...")
	conn, err := connect()
	if err != nil {
		fmt.Printf("[ERR] 连接失败: %v\n", err)
		return
	}
	defer conn.Close()

	req := GatewayRequest{
		Cmd:             "CMD_VERSION",
		LauncherVersion: strPtr("2.0.0"),
	}
	data, _ := json.Marshal(req)
	if err := sendFrame(conn, data); err != nil {
		fmt.Printf("[ERR] 发送失败: %v\n", err)
		return
	}

	respData, err := readFrame(conn)
	if err != nil {
		fmt.Printf("[ERR] 读取失败: %v\n", err)
		return
	}

	var resp GatewayResponse
	if err := json.Unmarshal(respData, &resp); err != nil {
		fmt.Printf("[ERR] 解析失败: %v\n", err)
		return
	}

	if !resp.Ok {
		fmt.Printf("[FAIL] 版本检查失败: code=%d msg=%v\n", resp.ErrorCode, deref(resp.Message))
		return
	}

	fmt.Printf("[OK] 版本检查通过!\n")
	fmt.Printf("  MinVersion: %s\n", deref(resp.Version))
}

func cmdAccountInfo(account string) {
	fmt.Printf("[TEST] 查询账号信息: %s\n", account)
	conn, err := connect()
	if err != nil {
		fmt.Printf("[ERR] 连接失败: %v\n", err)
		return
	}
	defer conn.Close()

	req := GatewayRequest{
		Cmd:     "CMD_ACCOUNT_INFO",
		Account: strPtr(account),
		AuthKey: strPtr("s4a21-admin-key-2026-secure-random-xyz"),
	}
	data, _ := json.Marshal(req)
	if err := sendFrame(conn, data); err != nil {
		fmt.Printf("[ERR] 发送失败: %v\n", err)
		return
	}

	respData, err := readFrame(conn)
	if err != nil {
		fmt.Printf("[ERR] 读取失败: %v\n", err)
		return
	}

	var resp GatewayResponse
	if err := json.Unmarshal(respData, &resp); err != nil {
		fmt.Printf("[ERR] 解析失败: %v\n", err)
		return
	}

	if !resp.Ok {
		fmt.Printf("[FAIL] 查询失败: code=%d msg=%v\n", resp.ErrorCode, deref(resp.Message))
		return
	}

	fmt.Printf("[OK] 账号信息:\n")
	fmt.Printf("  MId: %s\n", deref(resp.MId))
	fmt.Printf("  Cera: %d\n", int64Deref(resp.Cera))
	fmt.Printf("  TokenCera: %d\n", int64Deref(resp.TokenCera))
	fmt.Printf("  HappyTokenCera: %d\n", int64Deref(resp.HappyTokenCera))
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func int64Deref(i *int64) int64 {
	if i == nil {
		return 0
	}
	return *i
}

func boolDeref(b *bool) bool {
	if b == nil {
		return false
	}
	return *b
}

func cmdRegister(account, password string) {
	fmt.Printf("[TEST] 注册: %s\n", account)
	conn, err := connect()
	if err != nil {
		fmt.Printf("[ERR] 连接失败: %v\n", err)
		return
	}
	defer conn.Close()

	req := GatewayRequest{
		Cmd:             "CMD_REGISTER",
		Account:         strPtr(account),
		PasswordMd5:     strPtr(password),
		LauncherVersion: strPtr("2.0.0"),
	}
	data, _ := json.Marshal(req)
	if err := sendFrame(conn, data); err != nil {
		fmt.Printf("[ERR] 发送失败: %v\n", err)
		return
	}

	respData, err := readFrame(conn)
	if err != nil {
		fmt.Printf("[ERR] 读取失败: %v\n", err)
		return
	}

	var resp GatewayResponse
	if err := json.Unmarshal(respData, &resp); err != nil {
		fmt.Printf("[ERR] 解析失败: %v\n", err)
		return
	}

	if !resp.Ok {
		fmt.Printf("[FAIL] 注册失败: code=%d msg=%v\n", resp.ErrorCode, deref(resp.Message))
		return
	}

	fmt.Printf("[OK] 注册成功!\n")
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("用法:")
		fmt.Println("  test-launcher register <account> <password_md5>")
		fmt.Println("  test-launcher login <account> <password_md5> [device_secret]")
		fmt.Println("  test-launcher version")
		fmt.Println("  test-launcher info <account>")
		fmt.Println("")
		fmt.Println("示例:")
		fmt.Println("  test-launcher register testuser 5d41402abc4b2a76b9719d911017c592")
		fmt.Println("  test-launcher login testuser 5d41402abc4b2a76b9719d911017c592 abc123")
		fmt.Println("  test-launcher version")
		fmt.Println("  test-launcher info testuser")
		os.Exit(1)
	}

	cmd := os.Args[1]
	switch cmd {
	case "register":
		if len(os.Args) < 4 {
			fmt.Println("用法: test-launcher register <account> <password_md5>")
			os.Exit(1)
		}
		cmdRegister(os.Args[2], os.Args[3])
	case "login":
		if len(os.Args) < 4 {
			fmt.Println("用法: test-launcher login <account> <password_md5> [device_secret]")
			os.Exit(1)
		}
		account := os.Args[2]
		password := os.Args[3]
		deviceSecret := "abc123"
		if len(os.Args) >= 5 {
			deviceSecret = os.Args[4]
		}
		cmdLogin(account, password, deviceSecret)
	case "version":
		cmdVersion()
	case "info":
		if len(os.Args) < 3 {
			fmt.Println("用法: test-launcher info <account>")
			os.Exit(1)
		}
		cmdAccountInfo(os.Args[2])
	default:
		fmt.Printf("未知命令: %s\n", cmd)
		os.Exit(1)
	}
}
