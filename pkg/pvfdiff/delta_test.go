package pvfdiff

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ⑨ 滚动 adler32 必须与「整窗重算」逐位一致。
//    ★ 这条断言不是可有可无的：滚动实现写错**不会让合成失败**（字面量兜底），
//    只会让匹配率静默下降、delta 悄悄变大 —— 属于最难发现的一类劣化。
func TestAdlerRollMatchesSum(t *testing.T) {
	data := randBytes(11, 64<<10)
	const bs = 512
	a, b := adlerInit(data[:bs])
	for i := 0; i+bs < len(data); i++ {
		got := (b << 16) | a
		want := adler32Sum(data[i : i+bs])
		if got != want {
			t.Fatalf("第 %d 步不一致: roll=%08X sum=%08X", i, got, want)
		}
		a, b = adlerRoll(a, b, data[i], data[i+bs], bs)
	}
}

// 用伪随机数据而不是可压缩文本 —— PVF 的 body 是 zlib 分块，熵接近随机，
// 拿重复率高的假数据测会得到过于乐观的增量。
func randBytes(seed int64, n int) []byte {
	r := rand.New(rand.NewSource(seed))
	b := make([]byte, n)
	r.Read(b)
	return b
}

func writeTemp(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatalf("写 %s 失败: %v", name, err)
	}
	return p
}

// 与项目口径一致：PVF 指纹统一大写（security.FileFingerprintAlgo）。
func sha256OfFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读 %s 失败: %v", path, err)
	}
	sum := sha256.Sum256(b)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// roundTrip 生成 delta 并合成，断言逐字节一致，返回统计。
func roundTrip(t *testing.T, oldData, newData []byte, blockSize int) *Stats {
	t.Helper()
	dir := t.TempDir()
	oldPath := writeTemp(t, dir, "old.pvf", oldData)
	newPath := writeTemp(t, dir, "new.pvf", newData)
	deltaPath := filepath.Join(dir, "d.bin")
	outPath := filepath.Join(dir, "out.pvf")

	st, err := Build(oldPath, newPath, deltaPath, blockSize)
	if err != nil {
		t.Fatalf("Build 失败: %v", err)
	}
	if err := Apply(oldPath, deltaPath, outPath); err != nil {
		t.Fatalf("Apply 失败: %v", err)
	}

	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, newData) {
		t.Fatalf("合成结果与目标不一致：长度 %d vs %d", len(got), len(newData))
	}
	if h := sha256OfFile(t, outPath); h != st.ToHash || h != sha256OfFile(t, newPath) {
		t.Fatalf("SHA-256 不一致: out=%s stats.ToHash=%s", h, st.ToHash)
	}
	return st
}

// ① 内容完全没变 ⇒ 应当几乎全是 COPY（只可能因块边界有一小截字面量）。
func TestUnchangedIsAlmostAllCopy(t *testing.T) {
	data := randBytes(1, 4<<20)
	st := roundTrip(t, data, data, DefaultBlockSize)

	if st.InstrCount == 0 {
		t.Fatal("没有任何指令")
	}
	// 允许块边界造成的少量字面量（每个扫描 chunk 边界最多一个窗口）
	if st.LiteralSize > 64<<10 {
		t.Fatalf("未改动却产生了 %d 字节字面量（应当接近 0）", st.LiteralSize)
	}
	if st.DeltaRatio() > 0.01 {
		t.Fatalf("未改动时 delta 占比 %.4f，应当 < 1%%", st.DeltaRatio())
	}
}

// ② 只改中间 1 个字节 ⇒ 增量应当极小（这是 PVF「改数值」场景的模型）。
func TestModifyOneByteIsTiny(t *testing.T) {
	oldData := randBytes(2, 4<<20)
	newData := append([]byte(nil), oldData...)
	newData[2<<20] ^= 0xFF

	st := roundTrip(t, oldData, newData, DefaultBlockSize)

	if st.DeltaRatio() > 0.02 {
		t.Fatalf("改 1 字节的 delta 占比 %.4f（%d 字节），应当 < 2%%",
			st.DeltaRatio(), st.DeltaSize)
	}
}

// ③ 中间插入一段导致后续整体平移 ⇒ 滑动匹配必须能重新对上（这是固定偏移比对的死穴）。
func TestInsertShiftsAndStillMatches(t *testing.T) {
	oldData := randBytes(3, 4<<20)
	ins := randBytes(31, 4096)
	newData := append(append(append([]byte(nil), oldData[:1<<20]...), ins...), oldData[1<<20:]...)

	st := roundTrip(t, oldData, newData, DefaultBlockSize)

	// 平移之后仍有 99% 以上可以复用；能对上就说明滑动匹配生效了
	if st.DeltaRatio() > 0.02 {
		t.Fatalf("插入后 delta 占比 %.4f，说明平移之后没能重新匹配上", st.DeltaRatio())
	}
	if st.CopyBytes < int64(len(oldData))*9/10 {
		t.Fatalf("COPY 复用字节只有 %d，期望 >= 90%% 的旧文件", st.CopyBytes)
	}
}

// ④ 删除中间一段（反向平移）。
func TestDeleteShiftsAndStillMatches(t *testing.T) {
	oldData := randBytes(4, 4<<20)
	newData := append(append([]byte(nil), oldData[:1<<20]...), oldData[1<<20+8192:]...)

	st := roundTrip(t, oldData, newData, DefaultBlockSize)
	if st.DeltaRatio() > 0.02 {
		t.Fatalf("删除后 delta 占比 %.4f", st.DeltaRatio())
	}
}

// ⑤ 内容完全不同 ⇒ 全字面量，但合成必须仍然正确。
func TestCompletelyDifferent(t *testing.T) {
	oldData := randBytes(5, 1<<20)
	newData := randBytes(6, 1<<20)

	st := roundTrip(t, oldData, newData, DefaultBlockSize)
	if st.CopyBytes != 0 {
		t.Fatalf("完全不同的数据却复用了 %d 字节", st.CopyBytes)
	}
	if st.LiteralSize != int64(len(newData)) {
		t.Fatalf("字面量 %d，期望 %d", st.LiteralSize, len(newData))
	}
}

// ⑥ 边界：空文件、小于一个块、正好一个块、非整数倍。
func TestEdgeSizes(t *testing.T) {
	cases := []struct {
		name    string
		oldSize int
		newSize int
	}{
		{"空→空", 0, 0},
		{"空→有", 0, 3000},
		{"有→空", 3000, 0},
		{"小于一块", 1000, 1000},
		{"正好一块", 2048, 2048},
		{"非整数倍", 2048*3 + 17, 2048*3 + 17},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			oldData := randBytes(7, c.oldSize)
			newData := randBytes(8, c.newSize)
			roundTrip(t, oldData, newData, DefaultBlockSize)
		})
	}
}

// ⑦ 非默认块大小（保证 blockSize 参数真的被用上，而不是写死 2048）。
func TestCustomBlockSize(t *testing.T) {
	oldData := randBytes(9, 1<<20)
	newData := append([]byte(nil), oldData...)
	newData[500<<10] ^= 0x5A

	st := roundTrip(t, oldData, newData, 8192)
	if st.DeltaRatio() > 0.05 {
		t.Fatalf("块 8192 时 delta 占比 %.4f", st.DeltaRatio())
	}
}

// ⑧ 头部损坏 / 魔数错误必须被拒绝（合成方绝不能"凑合"出一份坏文件）。
func TestApplyRejectsBadMagic(t *testing.T) {
	dir := t.TempDir()
	oldPath := writeTemp(t, dir, "old.pvf", randBytes(10, 4096))
	bad := writeTemp(t, dir, "bad.bin", []byte("XXXXXXXX...................."))

	if err := Apply(oldPath, bad, filepath.Join(dir, "out")); err == nil {
		t.Fatal("魔数错误时 Apply 应当报错")
	}
}
