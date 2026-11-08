package httprouter

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newGoldBuybackTestServer 把配置文件指向 t.TempDir()，避免污染工作目录。
func newGoldBuybackTestServer(t *testing.T) *Server {
	t.Helper()
	prev := goldConsignBuybackConfigPath
	goldConsignBuybackConfigPath = filepath.Join(t.TempDir(), "gold_consign_buyback.json")
	t.Cleanup(func() { goldConsignBuybackConfigPath = prev })
	return &Server{}
}

func TestGoldConsignBuybackInternalConfigEmptyIsNull(t *testing.T) {
	s := newGoldBuybackTestServer(t)
	rec := httptest.NewRecorder()
	s.handleInternalGoldConsignBuybackConfig(rec, httptest.NewRequest("GET", "/internal/gold-consign-buyback/config", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// 从没配过 ⇒ revision 0 + config null，服务端据此保持「什么都不做」。
	if resp["revision"].(float64) != 0 {
		t.Fatalf("revision = %v, want 0", resp["revision"])
	}
	if v, ok := resp["config"]; !ok || v != nil {
		t.Fatalf("config = %v, want null", v)
	}
}

func TestGoldConsignBuybackAdminPostIncrementsRevision(t *testing.T) {
	s := newGoldBuybackTestServer(t)

	post := func(body string) map[string]interface{} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/api/admin/gold-consign-buyback/config", strings.NewReader(body))
		s.handleAdminGoldConsignBuybackConfigPost(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("post status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var out map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return out
	}

	first := post(`{"enabled":false,"dryRun":true,"goldCeraPer500k":100}`)
	if first["revision"].(float64) != 1 {
		t.Fatalf("first revision = %v, want 1", first["revision"])
	}
	second := post(`{"enabled":true,"dryRun":false,"goldCeraPer500k":80}`)
	if second["revision"].(float64) != 2 {
		t.Fatalf("second revision = %v, want 2（必须自增）", second["revision"])
	}

	// 读回来确认内容真的落盘了
	rec := httptest.NewRecorder()
	s.handleInternalGoldConsignBuybackConfig(rec, httptest.NewRequest("GET", "/internal/gold-consign-buyback/config", nil))
	var resp struct {
		OK       bool            `json:"ok"`
		Revision int64           `json:"revision"`
		Config   json.RawMessage `json:"config"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.OK || resp.Revision != 2 {
		t.Fatalf("ok=%v revision=%d, want true/2", resp.OK, resp.Revision)
	}
	var cfg struct {
		Enabled         bool `json:"enabled"`
		DryRun          bool `json:"dryRun"`
		GoldCeraPer500k int  `json:"goldCeraPer500k"`
	}
	if err := json.Unmarshal(resp.Config, &cfg); err != nil {
		t.Fatalf("decode config: %v", err)
	}
	if !cfg.Enabled || cfg.DryRun || cfg.GoldCeraPer500k != 80 {
		t.Fatalf("config = %+v, want enabled/dryRun=false/80", cfg)
	}
}

func TestGoldConsignBuybackAdminPostAcceptsEnvelope(t *testing.T) {
	s := newGoldBuybackTestServer(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/admin/gold-consign-buyback/config",
		strings.NewReader(`{"config":{"enabled":true,"goldCeraPer500k":120}}`))
	s.handleAdminGoldConsignBuybackConfigPost(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	// 包装层要被剥掉，落盘的是内层对象
	cfg := loadGoldConsignBuybackConfig()
	var inner map[string]json.RawMessage
	if err := json.Unmarshal(cfg.Config, &inner); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, wrapped := inner["config"]; wrapped {
		t.Fatalf("落盘仍是包装层: %s", string(cfg.Config))
	}
	if _, ok := inner["enabled"]; !ok {
		t.Fatalf("落盘缺 enabled: %s", string(cfg.Config))
	}
}

func TestGoldConsignBuybackAdminPostRejectsNonObject(t *testing.T) {
	s := newGoldBuybackTestServer(t)
	for _, body := range []string{`[1,2,3]`, `"text"`, `123`, ``} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/api/admin/gold-consign-buyback/config", strings.NewReader(body))
		s.handleAdminGoldConsignBuybackConfigPost(rec, req)
		if rec.Code == http.StatusOK {
			t.Fatalf("body %q 应被拒绝，实际 200", body)
		}
	}
}

func TestGoldConsignBuybackBrokenFileDegradesToNull(t *testing.T) {
	s := newGoldBuybackTestServer(t)
	// 手工写一份坏文件
	if err := os.WriteFile(goldConsignBuybackConfigPath, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	s.handleInternalGoldConsignBuybackConfig(rec, httptest.NewRequest("GET", "/internal/gold-consign-buyback/config", nil))
	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// 坏文件必须退化成 null（= 什么都不做），不能返回半截内容
	if v := resp["config"]; v != nil {
		t.Fatalf("config = %v, want null（坏文件应退化为 null）", v)
	}
}
