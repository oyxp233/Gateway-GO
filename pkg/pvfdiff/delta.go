// Package pvfdiff 把「旧文件 → 新文件」的差异编码成一份极简的 COPY/LITERAL 指令流，
// 供客户端（登录器）与本地旧文件合成出新文件。
//
// ============================================================================
// 为什么自研而不用 VCDIFF / xdelta
//
//  1. 客户端是 **自包含单文件 exe**（127.7 MiB）。引第三方库要重新论证体积、许可证
//     与安全边界，而这里只需要「固定块 + 滑动匹配」一个能力，VCDIFF 的字典/窗口
//     等特性完全用不上。
//  2. 格式越简单，**客户端合成器的出错面越小**。本格式只有 2 种指令，
//     C# 侧解释器约 150 行，且不需要任何哈希算法（合成方只按指令搬运字节，
//     真正的正确性由整文件 SHA-256 兜底）。
//  3. 实测 PVF 的差分指令只有 3~6 条（见 交付物/登录器增量更新可行性评估-*.md §3.2）
//     ⇒ VCDIFF 那点指令压缩收益可以忽略，delta ≈ 字面量本身。
//
// ============================================================================
// 文件格式（全部小端）
//
//	偏移  长度  字段
//	0     4     magic      = "A21D"
//	4     1     version    = 1
//	5     4     blockSize  生成时用的块大小（合成方只用于日志，不参与解析）
//	9     32    fromHash   旧文件的 SHA-256 原始字节（不是 hex）
//	41    32    toHash     新文件的 SHA-256 原始字节
//	73    8     toSize     新文件字节数
//	81    4     instrCount 指令条数
//	85    8     instrSize  指令流字节数
//	93    8     literalSize 字面量区字节数
//	101         —          指令流（instrSize 字节）
//	101+instrSize  —       字面量区（literalSize 字节）
//
// 指令：
//
//	COPY    0x01 | offset uint64 | length uint32   —— 从**旧文件**的 offset 处拷 length 字节
//	LITERAL 0x02 | length uint32                   —— 从**字面量区**按顺序取 length 字节
//
// ★ 合成方必须校验：fromHash == 本地旧文件的 SHA-256、最终产物 SHA-256 == toHash。
//   任一不符 ⇒ 丢弃产物，**保留旧文件**（绝不能留下半截文件）。
//
// ============================================================================
// 内存与性能
//
// 峰值内存 ≈ 一个 chunk（8 MiB）+ 旧文件块索引（每 2 KiB 一条 ≈ 文件大小/2048×16 B
// ≈ 75 MB 文件 0.6 MB），**不随文件大小线性增长到整文件**。
// 实测 74.9 MB 的 PVF：生成 1~2 s（本地 SSD）。
package pvfdiff

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"io"
	"os"
)

// 格式常量。
const (
	Magic            = "A21D"
	Version          = 1
	HeaderSize       = 101
	DefaultBlockSize = 2048

	opCopy    = byte(0x01)
	opLiteral = byte(0x02)

	// scanChunk 每次读入的扫描窗口大小。8 MiB 兼顾内存与系统调用次数。
	scanChunk = 8 << 20

	// literalFlush 字面量在内存里攒到这么大就先落一条 LITERAL 指令并刷盘，
	// 保证「全是字面量」的最坏情况下内存也不膨胀。
	literalFlush = 1 << 20
)

// Stats 是一次差分的结果统计，直接用于日志与验收断言。
type Stats struct {
	FromHash    string // 旧文件 SHA-256（hex 大写）
	ToHash      string // 新文件 SHA-256（hex 大写）
	ToSize      int64  // 新文件字节数
	DeltaSize   int64  // delta 包字节数（含 101 B 头部）
	InstrCount  int    // 指令条数
	InstrBytes  int64  // 指令流字节数
	LiteralSize int64  // 字面量字节数
	CopyBytes   int64  // 通过 COPY 复用的字节数
}

// DeltaRatio 返回 delta / 新文件 的比值（0~1）。新文件为空时返回 0。
func (s *Stats) DeltaRatio() float64 {
	if s.ToSize <= 0 {
		return 0
	}
	return float64(s.DeltaSize) / float64(s.ToSize)
}

type blockRef struct {
	strong uint64
	off    int64
}

// Build 生成 oldPath → newPath 的 delta，写到 outPath。
//
// blockSize <= 0 时用 DefaultBlockSize。
func Build(oldPath, newPath, outPath string, blockSize int) (*Stats, error) {
	if blockSize <= 0 {
		blockSize = DefaultBlockSize
	}

	oldF, err := os.Open(oldPath)
	if err != nil {
		return nil, fmt.Errorf("打开旧文件失败: %w", err)
	}
	defer oldF.Close()

	newF, err := os.Open(newPath)
	if err != nil {
		return nil, fmt.Errorf("打开新文件失败: %w", err)
	}
	defer newF.Close()

	newInfo, err := newF.Stat()
	if err != nil {
		return nil, err
	}
	toSize := newInfo.Size()

	// ① 索引旧文件：逐块算「弱哈希 adler32 + 强哈希 fnv64」，顺带算整文件 SHA-256。
	fromHashBytes, refs, err := indexOld(oldF, blockSize)
	if err != nil {
		return nil, fmt.Errorf("索引旧文件失败: %w", err)
	}

	// ② 扫描新文件，产出指令流与字面量。
	litPath := outPath + ".lit.tmp"
	litF, err := os.Create(litPath)
	if err != nil {
		return nil, err
	}
	defer func() {
		litF.Close()
		os.Remove(litPath) // 无论成败都不留临时文件
	}()
	litW := bufio.NewWriterSize(litF, 1<<20)

	instrs := &instrBuf{}
	sc := &scanner{f: newF, size: toSize, bs: blockSize, buf: make([]byte, scanChunk+blockSize)}

	toHash, err := sc.scan(refs, instrs, litW)
	if err != nil {
		return nil, fmt.Errorf("扫描新文件失败: %w", err)
	}
	if err := litW.Flush(); err != nil {
		return nil, err
	}

	// ③ 拼装：header + 指令流 + 字面量区。
	out, err := os.Create(outPath)
	if err != nil {
		return nil, err
	}
	defer out.Close()
	w := bufio.NewWriterSize(out, 1<<20)

	litInfo, err := litF.Stat()
	if err != nil {
		return nil, err
	}

	hdr := make([]byte, HeaderSize)
	copy(hdr[0:4], Magic)
	hdr[4] = Version
	binary.LittleEndian.PutUint32(hdr[5:9], uint32(blockSize))
	copy(hdr[9:41], fromHashBytes)
	copy(hdr[41:73], toHash)
	binary.LittleEndian.PutUint64(hdr[73:81], uint64(toSize))
	binary.LittleEndian.PutUint32(hdr[81:85], uint32(instrs.count))
	binary.LittleEndian.PutUint64(hdr[85:93], uint64(len(instrs.data)))
	binary.LittleEndian.PutUint64(hdr[93:101], uint64(litInfo.Size()))

	if _, err := w.Write(hdr); err != nil {
		return nil, err
	}
	if _, err := w.Write(instrs.data); err != nil {
		return nil, err
	}
	if _, err := litF.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	if _, err := io.Copy(w, litF); err != nil {
		return nil, err
	}
	if err := w.Flush(); err != nil {
		return nil, err
	}

	dst, err := out.Stat()
	if err != nil {
		return nil, err
	}

	return &Stats{
		FromHash:    upperHex(fromHashBytes),
		ToHash:      upperHex(toHash),
		ToSize:      toSize,
		DeltaSize:   dst.Size(),
		InstrCount:  instrs.count,
		InstrBytes:  int64(len(instrs.data)),
		LiteralSize: litInfo.Size(),
		CopyBytes:   instrs.copyBytes,
	}, nil
}

// instrBuf 累积指令流。指令流很小（每条 13 B，上限 = 文件大小/块大小），放内存即可。
type instrBuf struct {
	data      []byte
	count     int
	copyBytes int64
}

// addCopy 追加一条 COPY。★ 若上一条也是 COPY 且与本条**首尾相接**
// （prevOff+prevLen == off），就地把它的长度加长 —— 否则 74.9 MB 的 PVF 会产出
// 3.6 万条「每块一条」的指令，指令流自己就 474 KB，比字面量还大。
// 合并后指令流通常只有几十字节，delta 大小 ≈ 字面量本身（实测 0.29% ~ 0.93%）。
func (b *instrBuf) addCopy(off int64, length int) {
	if n := len(b.data); n >= 13 && b.data[n-13] == opCopy {
		prevOff := int64(binary.LittleEndian.Uint64(b.data[n-12 : n-4]))
		prevLen := int(binary.LittleEndian.Uint32(b.data[n-4 : n]))
		if prevOff+int64(prevLen) == off {
			binary.LittleEndian.PutUint32(b.data[n-4:n], uint32(prevLen+length))
			b.copyBytes += int64(length)
			return
		}
	}

	var tmp [13]byte
	tmp[0] = opCopy
	binary.LittleEndian.PutUint64(tmp[1:9], uint64(off))
	binary.LittleEndian.PutUint32(tmp[9:13], uint32(length))
	b.data = append(b.data, tmp[:]...)
	b.count++
	b.copyBytes += int64(length)
}

func (b *instrBuf) addLiteral(length int) {
	var tmp [5]byte
	tmp[0] = opLiteral
	binary.LittleEndian.PutUint32(tmp[1:5], uint32(length))
	b.data = append(b.data, tmp[:]...)
	b.count++
}

// indexOld 按 blockSize 给旧文件建索引，同时算出整文件 SHA-256。
// 末尾不足一整块的部分不索引（合成时走 LITERAL，最多损失 blockSize-1 字节的复用）。
func indexOld(f *os.File, bs int) ([]byte, map[uint32][]blockRef, error) {
	h := sha256.New()
	refs := make(map[uint32][]blockRef)
	buf := make([]byte, bs)
	var off int64

	for {
		n, err := io.ReadFull(f, buf)
		if n > 0 {
			h.Write(buf[:n])
		}
		if n == bs {
			w := adler32Sum(buf)
			refs[w] = append(refs[w], blockRef{strong: fnv64(buf), off: off})
			off += int64(n)
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return h.Sum(nil), refs, nil
		}
		if err != nil {
			return nil, nil, err
		}
	}
}

// scanner 在新文件上做「逐字节滑动 + 块匹配」。
//
// 缓冲区一次读入 scanChunk+blockSize 字节，保证窗口 [pos, pos+bs) 完整落在缓冲内；
// 当 pos 推近缓冲尾部时重新填充。块边界处最多损失一个窗口的复用机会
// （2 KiB × 文件大小/8 MiB 个边界，对 75 MB 的文件不到 20 KiB），换来恒定内存。
type scanner struct {
	f    *os.File
	size int64
	bs   int
	buf  []byte
	base int64 // buf[0] 对应的文件偏移
	n    int   // buf 中有效字节数
}

// ensure 保证 [pos, pos+bs) 落在缓冲内。返回 false 表示文件剩余不足一个窗口
// （调用方把剩下的字节全按字面量处理）。
func (s *scanner) ensure(pos int64) bool {
	need := pos + int64(s.bs)
	if pos >= s.base && need <= s.base+int64(s.n) {
		return true
	}
	s.base = pos
	n, err := s.f.ReadAt(s.buf, pos)
	if n <= 0 && err != nil {
		s.n = 0
		return false
	}
	s.n = n
	return int64(n) >= int64(s.bs)
}

// scan 滑动新文件产出指令，返回新文件的 SHA-256。
func (s *scanner) scan(refs map[uint32][]blockRef, instrs *instrBuf, litW *bufio.Writer) ([]byte, error) {
	h := sha256.New()
	var pos int64
	var pending []byte // 尚未成条的字面量

	flushLiteral := func() error {
		if len(pending) == 0 {
			return nil
		}
		instrs.addLiteral(len(pending))
		if _, err := litW.Write(pending); err != nil {
			return err
		}
		pending = pending[:0]
		return nil
	}

	// rollOK 表示 wa/wb 是否仍对应当前窗口。窗口整体跳转（COPY 之后）或
	// 即将移出缓冲时置 false，下一轮用 adlerInit 重算。
	var wa, wb uint32
	rollOK := false

	for pos < s.size {
		if !s.ensure(pos) {
			break
		}
		from := int(pos - s.base)
		win := s.buf[from : from+s.bs]

		if !rollOK {
			wa, wb = adlerInit(win)
			rollOK = true
		}
		w := (wb << 16) | wa

		hit := false
		var hitOff int64
		if cands, ok := refs[w]; ok {
			strong := fnv64(win)
			for _, c := range cands {
				if c.strong == strong {
					hit = true
					hitOff = c.off
					break
				}
			}
		}

		if hit {
			if err := flushLiteral(); err != nil {
				return nil, err
			}
			instrs.addCopy(hitOff, s.bs)
			h.Write(win)
			pos += int64(s.bs)
			rollOK = false // 窗口整体跳走，下轮重算
			continue
		}

		// 未命中：把窗口首字节并进字面量，窗口右移 1 字节（滚动更新，O(1)）。
		pending = append(pending, win[0])
		h.Write(win[:1])
		if from+s.bs < s.n {
			wa, wb = adlerRoll(wa, wb, win[0], s.buf[from+s.bs], s.bs)
		} else {
			rollOK = false // 新窗口要移出缓冲，下一轮重填后重算
		}
		pos++
		if len(pending) >= literalFlush {
			if err := flushLiteral(); err != nil {
				return nil, err
			}
		}
	}

	// 尾部剩余（不足一个窗口）全部按字面量处理。
	if pos < s.size {
		tail := make([]byte, s.size-pos)
		if _, err := s.f.ReadAt(tail, pos); err != nil && err != io.EOF {
			return nil, err
		}
		h.Write(tail)
		pending = append(pending, tail...)
		if len(pending) >= literalFlush {
			if err := flushLiteral(); err != nil {
				return nil, err
			}
		}
	}
	if err := flushLiteral(); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// ============================================================================
// 合成（Apply）—— 服务端自测用，同时也是客户端 C# 合成器的参照实现。
// 两边行为必须逐字节一致，否则线上会出现「网关自己测得通、玩家却合成失败」。
// ============================================================================

// Apply 用 oldPath + deltaPath 合成出 outPath。
func Apply(oldPath, deltaPath, outPath string) error {
	df, err := os.Open(deltaPath)
	if err != nil {
		return err
	}
	defer df.Close()

	hdr := make([]byte, HeaderSize)
	if _, err := io.ReadFull(df, hdr); err != nil {
		return fmt.Errorf("读 delta 头部失败: %w", err)
	}
	if string(hdr[0:4]) != Magic {
		return fmt.Errorf("delta 魔数不符: %q", hdr[0:4])
	}
	if hdr[4] != Version {
		return fmt.Errorf("delta 版本不支持: %d", hdr[4])
	}
	toSize := int64(binary.LittleEndian.Uint64(hdr[73:81]))
	instrCount := int(binary.LittleEndian.Uint32(hdr[81:85]))
	instrSize := int64(binary.LittleEndian.Uint64(hdr[85:93]))
	literalSize := int64(binary.LittleEndian.Uint64(hdr[93:101]))

	oldF, err := os.Open(oldPath)
	if err != nil {
		return err
	}
	defer oldF.Close()

	bf := bufio.NewReaderSize(df, 1<<20)
	instrs := make([]byte, instrSize)
	if _, err := io.ReadFull(bf, instrs); err != nil {
		return fmt.Errorf("读指令流失败: %w", err)
	}
	lit := io.LimitReader(bf, literalSize)

	out, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer out.Close()
	w := bufio.NewWriterSize(out, 1<<20)

	p := 0
	for i := 0; i < instrCount; i++ {
		op := instrs[p]
		p++
		switch op {
		case opCopy:
			off := int64(binary.LittleEndian.Uint64(instrs[p : p+8]))
			ln := int64(binary.LittleEndian.Uint32(instrs[p+8 : p+12]))
			p += 12
			if _, err := oldF.Seek(off, io.SeekStart); err != nil {
				return err
			}
			if _, err := io.CopyN(w, oldF, ln); err != nil {
				return fmt.Errorf("COPY 失败(off=%d len=%d): %w", off, ln, err)
			}
		case opLiteral:
			ln := int64(binary.LittleEndian.Uint32(instrs[p : p+4]))
			p += 4
			if _, err := io.CopyN(w, lit, ln); err != nil {
				return fmt.Errorf("LITERAL 失败(len=%d): %w", ln, err)
			}
		default:
			return fmt.Errorf("未知指令 0x%02X（第 %d 条）", op, i)
		}
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}

	st, err := os.Stat(outPath)
	if err != nil {
		return err
	}
	if st.Size() != toSize {
		return fmt.Errorf("合成结果大小不符: 得到 %d，期望 %d", st.Size(), toSize)
	}
	return nil
}

// ============================================================================
// 哈希
// ============================================================================

// adler32Sum 标准 adler32（mod 65521）。只用于「按块建立索引」——每块调一次。
func adler32Sum(b []byte) uint32 {
	const mod = 65521
	var a, s uint32 = 1, 0
	for _, c := range b {
		a = (a + uint32(c)) % mod
		s = (s + a) % mod
	}
	return (s << 16) | a
}

const adlerMod = 65521

// adlerInit 算窗口 [0,n) 的 adler 状态（返回 a、b 两个分量）。
// 调用频率 = COPY 次数 + 缓冲重填次数，都是低频，直接每步取模即可。
func adlerInit(win []byte) (uint32, uint32) {
	a, s := uint32(1), uint32(0)
	for _, c := range win {
		a = (a + uint32(c)) % adlerMod
		s = (s + a) % adlerMod
	}
	return a, s
}

// adlerRoll 把窗口右移一字节：移出 out、移入 in，窗口长度恒为 n。
//
//	★ 这是滑动扫描的性能命门：不做增量更新的话，每滑一字节都要重算整个窗口，
//	  74.9 MB 的 PVF 在「大面积失配」时会退化成 1500 亿次操作（实测 1 MB 就要 6.6 秒）。
//
// A' = A - out + in
// B' = B + A' - 1 - n*out
func adlerRoll(a, b uint32, out, in byte, n int) (uint32, uint32) {
	na := int64(a) - int64(out) + int64(in)
	nb := int64(b) + na - 1 - int64(n)*int64(out)

	na %= adlerMod
	if na < 0 {
		na += adlerMod
	}
	nb %= adlerMod
	if nb < 0 {
		nb += adlerMod
	}
	return uint32(na), uint32(nb)
}

// fnv64 强哈希，用于消除 adler32 碰撞。
func fnv64(b []byte) uint64 {
	h := fnv.New64a()
	h.Write(b)
	return h.Sum64()
}

// Header 是 delta 包的头部信息（不读指令与字面量）。
type Header struct {
	Version     byte
	BlockSize   int
	FromHash    string // 大写 hex
	ToHash      string // 大写 hex
	ToSize      int64
	InstrCount  int
	InstrBytes  int64
	LiteralSize int64
	TotalSize   int64
}

// Inspect 只读 delta 包的头部。网关用它判断「磁盘上这份增量包是不是当前 PVF 的」，
// 避免每次下发都去读 200 KB~11 MB 的正文。
func Inspect(path string) (*Header, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return nil, err
	}

	hdr := make([]byte, HeaderSize)
	if _, err := io.ReadFull(f, hdr); err != nil {
		return nil, fmt.Errorf("读头部失败: %w", err)
	}
	if string(hdr[0:4]) != Magic {
		return nil, fmt.Errorf("魔数不符: %q", hdr[0:4])
	}
	if hdr[4] != Version {
		return nil, fmt.Errorf("版本不支持: %d", hdr[4])
	}
	return &Header{
		Version:     hdr[4],
		BlockSize:   int(binary.LittleEndian.Uint32(hdr[5:9])),
		FromHash:    upperHex(hdr[9:41]),
		ToHash:      upperHex(hdr[41:73]),
		ToSize:      int64(binary.LittleEndian.Uint64(hdr[73:81])),
		InstrCount:  int(binary.LittleEndian.Uint32(hdr[81:85])),
		InstrBytes:  int64(binary.LittleEndian.Uint64(hdr[85:93])),
		LiteralSize: int64(binary.LittleEndian.Uint64(hdr[93:101])),
		TotalSize:   st.Size(),
	}, nil
}

func upperHex(b []byte) string {
	// sha256 摘要固定 32 字节
	dst := make([]byte, 64)
	hex.Encode(dst, b)
	for i, c := range dst {
		if c >= 'a' && c <= 'f' {
			dst[i] = c - 32
		}
	}
	return string(dst)
}
