package httprouter

import (
	"fmt"

	"s4a21-gateway/pkg/models"
	"s4a21-gateway/pkg/service"
)

// ============================================================================
// 公告后端抽象
//
// 为什么公告也要走这层：公告配置有**两份状态** —— 库里的行，和网关进程内存里的快照。
// 游戏服务端的插件每几秒从内部 API 拉的就是那份内存快照。
// 如果让 admin 进程直接写库，会出现「后台显示已改，插件拉到的还是旧的」——
// 直到网关重启才恢复一致。所以写操作必须由持有快照的一方执行。
//
// 分工：
//   AnnounceBackend（本接口）  配置读写 + 弹窗入队 —— 必须经网关
//   事件/弹窗历史/排行榜查询    handler 里直连 s.db —— 纯历史数据，各进程读都安全
//
// 之所以读能够绕过网关：announce_events / announce_popups 只追加、不依赖内存态，
// SQLite 在 WAL 下多进程只读没有一致性问题；反过来说，让 8443 的每个页面
// 都往 18080 绕一圈，只会把网关的可用性变成后台的可用性。
// ============================================================================

// AnnounceBackend 抽象"依赖网关内存态"的公告操作。
type AnnounceBackend interface {
	// Config 返回网关内存里的配置快照。
	Config() (models.AnnounceConfig, error)
	// UpdateConfig 保存配置并**立即热重载**（插件下个轮询周期即生效，不重启服务端）。
	UpdateConfig(cfg models.AnnounceConfig) (models.AnnounceConfig, error)
	// SendPopup 入队一条全服弹窗公告，返回记录 id。
	SendPopup(message string, mode int, createdBy string) (int64, error)
}

type localAnnounceBackend struct {
	svc *service.AnnounceService
}

// NewLocalAnnounceBackend 构造网关进程内的公告后端。
func NewLocalAnnounceBackend(svc *service.AnnounceService) AnnounceBackend {
	return &localAnnounceBackend{svc: svc}
}

func (b *localAnnounceBackend) err() error {
	return fmt.Errorf("公告服务未初始化")
}

func (b *localAnnounceBackend) Config() (models.AnnounceConfig, error) {
	if b.svc == nil {
		return models.DefaultAnnounceConfig(), b.err()
	}
	return b.svc.Config(), nil
}

func (b *localAnnounceBackend) UpdateConfig(cfg models.AnnounceConfig) (models.AnnounceConfig, error) {
	if b.svc == nil {
		return cfg, b.err()
	}
	return b.svc.UpdateConfig(cfg)
}

func (b *localAnnounceBackend) SendPopup(message string, mode int, createdBy string) (int64, error) {
	if b.svc == nil {
		return 0, b.err()
	}
	return b.svc.SendPopup(message, mode, createdBy)
}

type unavailableAnnounceBackend struct{ reason string }

// NewUnavailableAnnounceBackend 构造一个总是返回错误的公告后端。
func NewUnavailableAnnounceBackend(reason string) AnnounceBackend {
	return &unavailableAnnounceBackend{reason: reason}
}

func (b *unavailableAnnounceBackend) err() error {
	return fmt.Errorf("公告配置功能不可用：%s", b.reason)
}

func (b *unavailableAnnounceBackend) Config() (models.AnnounceConfig, error) {
	return models.DefaultAnnounceConfig(), b.err()
}

func (b *unavailableAnnounceBackend) UpdateConfig(cfg models.AnnounceConfig) (models.AnnounceConfig, error) {
	return cfg, b.err()
}

func (b *unavailableAnnounceBackend) SendPopup(string, int, string) (int64, error) {
	return 0, b.err()
}
