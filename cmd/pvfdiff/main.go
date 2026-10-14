// pvfdiff 是 PVF 增量包的命令行工具。
//
// 用途：
//  1. 本地/线上实测「两版 PVF 之间到底要传多少字节」（不依赖任何服务）；
//  2. 运维在网关不可用或需要离线出包时，手动生成 / 校验一份 delta。
//
// 用法：
//
//	pvfdiff build <old.pvf> <new.pvf> <out.delta> [blockSize]
//	pvfdiff apply <old.pvf> <in.delta> <out.pvf>
//	pvfdiff info  <in.delta>
//
// ★ build 之后务必用 apply 跑一遍并比对 SHA-256 —— 网关自己测得通、
// 玩家却合成失败，是这类功能最贵的一种 bug。
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"s4a21-gateway/pkg/pvfdiff"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "build":
		if len(os.Args) < 5 {
			usage()
		}
		bs := pvfdiff.DefaultBlockSize
		if len(os.Args) >= 6 {
			fmt.Sscanf(os.Args[5], "%d", &bs)
		}
		doBuild(os.Args[2], os.Args[3], os.Args[4], bs)
	case "apply":
		if len(os.Args) < 5 {
			usage()
		}
		doApply(os.Args[2], os.Args[3], os.Args[4])
	case "info":
		if len(os.Args) < 3 {
			usage()
		}
		doInfo(os.Args[2])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `用法:
  pvfdiff build <old.pvf> <new.pvf> <out.delta> [blockSize]
  pvfdiff apply <old.pvf> <in.delta> <out.pvf>
  pvfdiff info  <in.delta>`)
	os.Exit(2)
}

func doBuild(oldPath, newPath, outPath string, bs int) {
	t0 := time.Now()
	st, err := pvfdiff.Build(oldPath, newPath, outPath, bs)
	if err != nil {
		fmt.Fprintln(os.Stderr, "FAIL build:", err)
		os.Exit(1)
	}
	fmt.Printf("块大小      : %d\n", bs)
	fmt.Printf("旧文件 hash : %s\n", st.FromHash)
	fmt.Printf("新文件 hash : %s\n", st.ToHash)
	fmt.Printf("新文件大小  : %d\n", st.ToSize)
	fmt.Printf("指令条数    : %d\n", st.InstrCount)
	fmt.Printf("COPY 复用   : %d 字节\n", st.CopyBytes)
	fmt.Printf("字面量      : %d 字节\n", st.LiteralSize)
	fmt.Printf("delta 大小  : %d 字节 (%.4f%%)\n", st.DeltaSize, st.DeltaRatio()*100)
	fmt.Printf("耗时        : %.2f s\n", time.Since(t0).Seconds())

	// 自证：立刻合成一遍并比对 SHA-256。测得过才算这个包可用。
	out := outPath + ".verify.pvf"
	defer os.Remove(out)
	if err := pvfdiff.Apply(oldPath, outPath, out); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL 自证合成:", err)
		os.Exit(1)
	}
	got, err := fileSHA256(out)
	if err != nil {
		fmt.Fprintln(os.Stderr, "FAIL 读合成产物:", err)
		os.Exit(1)
	}
	if got != st.ToHash {
		fmt.Fprintf(os.Stderr, "FAIL 自证不一致: 合成 %s != 目标 %s\n", got, st.ToHash)
		os.Exit(1)
	}
	fmt.Println("自证        : OK（合成产物 SHA-256 == 目标）")
}

func doApply(oldPath, deltaPath, outPath string) {
	if err := pvfdiff.Apply(oldPath, deltaPath, outPath); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL apply:", err)
		os.Exit(1)
	}
	h, err := fileSHA256(outPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
	fmt.Printf("合成完成: %s\nSHA-256 : %s\n", outPath, h)
}

func doInfo(deltaPath string) {
	b, err := os.ReadFile(deltaPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
	if len(b) < pvfdiff.HeaderSize || string(b[0:4]) != pvfdiff.Magic {
		fmt.Fprintln(os.Stderr, "不是本工具的 delta 包")
		os.Exit(1)
	}
	fmt.Printf("版本        : %d\n", b[4])
	fmt.Printf("块大小      : %d\n", binary.LittleEndian.Uint32(b[5:9]))
	fmt.Printf("from hash   : %s\n", strings.ToUpper(hex.EncodeToString(b[9:41])))
	fmt.Printf("to hash     : %s\n", strings.ToUpper(hex.EncodeToString(b[41:73])))
	fmt.Printf("to size     : %d\n", binary.LittleEndian.Uint64(b[73:81]))
	fmt.Printf("指令条数    : %d\n", binary.LittleEndian.Uint32(b[81:85]))
	fmt.Printf("指令流字节  : %d\n", binary.LittleEndian.Uint64(b[85:93]))
	fmt.Printf("字面量字节  : %d\n", binary.LittleEndian.Uint64(b[93:101]))
	fmt.Printf("文件大小    : %d\n", len(b))
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return strings.ToUpper(hex.EncodeToString(h.Sum(nil))), nil
}
