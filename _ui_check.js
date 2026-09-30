
        let authKey = localStorage.getItem('authKey') || '';

        // ==================== 主题 ====================

        // 三套主题只是 <html data-theme="..."> 的取值，配色全在 CSS 变量里定义，
        // 这里一行颜色都不写。要加第四套主题，只需在 <style> 里再加一个块，
        // 再往下面 THEMES / 切换按钮里各加一项。
        const THEMES = ['light', 'dark', 'blue'];
        const THEME_KEY = 's4a21-theme';
        const DEFAULT_THEME = 'dark';

        // 立即执行：此时页面主体还没渲染完，切主题不会先闪一下默认配色。
        function applyTheme(name) {
            const t = THEMES.indexOf(name) >= 0 ? name : DEFAULT_THEME;
            document.documentElement.setAttribute('data-theme', t);
            document.querySelectorAll('#themeSwitch .theme-btn').forEach(btn => {
                btn.classList.toggle('active', btn.getAttribute('data-theme') === t);
            });
        }

        function setTheme(name) {
            const t = THEMES.indexOf(name) >= 0 ? name : DEFAULT_THEME;
            localStorage.setItem(THEME_KEY, t);
            applyTheme(t);
        }

        applyTheme(localStorage.getItem(THEME_KEY));

        // fmtGameTime 显示游戏库来的时间文本（形如 "2026-08-11 13:32:12"）。
        //
        // 游戏库的 CURRENT_TIMESTAMP 写的是 **UTC**，但字符串里不带时区后缀，
        // 直接 new Date() 会被当成本地时间，显示出来差好几个小时。手工补上 'Z'
        // 再解析，前端才会按浏览器所在时区换算。
        function fmtGameTime(s) {
            if (!s) return '';
            const t = Date.parse(String(s).replace(' ', 'T') + 'Z');
            // 认不出来的格式原样显示 —— 宁可不换算，也不能显示成空白。
            if (isNaN(t)) return String(s);
            return new Date(t).toLocaleString();
        }

        // ==================== 通用工具 ====================

        // HTML 转义：所有插入 innerHTML 的动态数据必须先过这里，
        // 否则账号名/封禁理由等可控字段可注入脚本，进而窃取 localStorage 中的管理密钥。
        function esc(v) {
            if (v === null || v === undefined) return '';
            return String(v)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#39;');
        }

        // 用于内联事件属性中的字符串字面量（如 onclick="f('...')"）：
        // 先做 JS 字符串转义，再做 HTML 属性转义。
        function escAttr(v) {
            return esc(JSON.stringify(String(v === null || v === undefined ? '' : v)).slice(1, -1));
        }

        // 为动态生成的行绑定动作：用事件委托替代内联 onclick，
        // 避免账号名等可控字段逃逸出 JS 字符串字面量执行任意脚本。
        function bindRowActions(container, attr, handlers) {
            container.querySelectorAll('[' + attr + ']').forEach(el => {
                const fn = handlers[el.getAttribute(attr)];
                if (fn) el.addEventListener('click', () => fn(el));
            });
        }

        function fmtTime(sec) {
            if (!sec) return '-';
            return new Date(sec * 1000).toLocaleString();
        }

        function fmtSize(n) {
            if (n === null || n === undefined) return '-';
            if (n < 1024) return n + ' B';
            if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
            if (n < 1024 * 1024 * 1024) return (n / 1024 / 1024).toFixed(1) + ' MB';
            return (n / 1024 / 1024 / 1024).toFixed(2) + ' GB';
        }

        function truncHash(h) {
            if (!h) return '-';
            return h.length > 20 ? h.slice(0, 12) + '…' + h.slice(-6) : h;
        }

        // 统一结果提示条。type: 'success' | 'error'
        function showResult(id, type, text) {
            const box = document.getElementById(id);
            if (!box) { alert(text); return; }
            box.innerHTML = `<div class="alert alert-${type}">${esc(text)}</div>`;
            if (type === 'success') setTimeout(() => { if (box.innerHTML.indexOf(esc(text)) >= 0) box.innerHTML = ''; }, 6000);
        }

        function setText(id, text) {
            const el = document.getElementById(id);
            if (el) el.innerText = text || '';
        }

        // ==================== 请求封装 ====================

        async function api(path, method = 'GET', body = null) {
            const headers = {
                'X-Auth-Key': authKey,
                'Content-Type': 'application/json'
            };
            const opts = { method, headers };
            if (body) opts.body = JSON.stringify(body);
            const resp = await fetch(path, opts);
            if (resp.status === 401) {
                alert('管理密钥错误或未设置');
                authKey = document.getElementById('authKey').value;
                localStorage.setItem('authKey', authKey);
                return null;
            }
            return await resp.json();
        }

        // 文件上传走 multipart，不能带 Content-Type（由浏览器自动生成 boundary）。
        async function upload(path, formData) {
            const resp = await fetch(path, {
                method: 'POST',
                headers: { 'X-Auth-Key': authKey },
                body: formData
            });
            if (resp.status === 401) {
                alert('管理密钥错误或未设置');
                return null;
            }
            return await resp.json();
        }

        // ==================== Tab 切换 ====================

        const tabLoaders = {
            online: loadOnline,
            accounts: () => loadAccounts(1),
            bans: loadBans,
            integrity: loadIntegrity,
            server: () => { loadServerStatus(); loadBackups(); loadRegisterBonus(); loadBonusConfig(); loadGameEvents(); },
            gateway: loadGatewayStatus,
            ports: loadGamePorts,
            anticheat: () => { loadAcPlayers(); loadAcDetections(); },
            launcher: loadLauncherConfig,
            maintenance: loadMaintenance,
            announce: () => { loadAnnounceConfig(); loadAnnouncePopups(1); loadAnnounceEvents(1); }
        };

        document.querySelectorAll('.tab').forEach(tab => {
            tab.addEventListener('click', () => {
                document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
                document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
                tab.classList.add('active');
                document.getElementById(tab.dataset.tab).classList.add('active');
                const loader = tabLoaders[tab.dataset.tab];
                if (loader) loader();
            });
        });

        // ==================== 在线玩家 ====================

        async function loadOnline() {
            const data = await api('/api/admin/online');
            if (!data) return;
            const tbody = document.getElementById('onlineTable');
            tbody.innerHTML = '';
            const players = data.players || [];
            setText('onlineCount', `共 ${players.length} 人在线`);
            players.forEach(p => {
                tbody.innerHTML += `<tr>
                    <td>${esc(p.account)}</td>
                    <td>${esc(p.ip)}</td>
                    <td>${esc(p.onlineMinutes)}分钟</td>
                    <td>${esc(fmtTime(p.lastHeartbeat))}</td>
                    <td>${esc(p.bonusGranted)}</td>
                    <td>${esc(p.cera)}</td>
                    <td><button class="btn btn-danger btn-sm" data-act="kick" data-account="${escAttr(p.account)}">踢下线</button></td>
                </tr>`;
            });
            bindRowActions(tbody, 'data-act', {
                kick: (el) => kickAccount(el.dataset.account)
            });
        }

        async function kickAccount(account) {
            await api('/api/admin/online/kick', 'POST', { account });
            loadOnline();
        }

        async function kickAll() {
            if (confirm('确定踢所有玩家下线？')) {
                await api('/api/admin/online/kick', 'POST', { account: '' });
                loadOnline();
            }
        }

        // ==================== 账号管理 ====================

        let accountPage = 1;
        // 每页数量：50 / 100 / 200 / 500，由页面上方的下拉选择。
        let accountPageSize = 50;

        function changeAccountPageSize() {
            const sel = document.getElementById('accountPageSize');
            accountPageSize = parseInt(sel.value, 10) || 50;
            loadAccounts(1);
        }

        // accountCreatedCell 渲染「注册时间」单元格。
        //
        // 以**游戏库**的注册时间为准：那才是玩家真正注册的时刻。网关库里那一列
        // 是本网关写库的时间戳，批量导入的账号会挤在同一秒（实测 9/24 那批全是
        // 09:41:36）—— 这就是本次报障"整列时间一模一样"的根因。
        //
        // 游戏库还没有该账号时（注册了但没进过游戏，服务端尚未懒建行），回落到
        // 网关库时间，并在单元格里明确标出来，免得看的人把它当成真注册时间。
        function accountCreatedCell(a) {
            if (a.game_created_at) return esc(fmtGameTime(a.game_created_at));
            return esc(fmtTime(a.created_at)) +
                ' <span class="muted" title="游戏库里还没有这个账号（注册后未进过游戏），这里显示的是网关库时间">网关库</span>';
        }

        // 状态列：账号状态（正常 / 封禁 / 锁定）+ 在线状态（在线 / 离线）。
        //
        // 两个维度分开显示，不合成一个"异常"：封禁要管理员手动解封，
        // 锁定是连续登录失败自动触发的（到期自解），处置方式完全不同。
        function accountStatusCell(a) {
            const acct = a.banned
                ? '<span class="tag tag-off">封禁</span>'
                : (a.locked
                    ? '<span class="tag tag-warn" title="连续登录失败已锁定，可点「解锁」立即解除">锁定</span>'
                    : '<span class="tag tag-on">正常</span>');
            const net = a.online
                ? '<span class="tag tag-on">在线</span>'
                : '<span class="tag tag-neutral">离线</span>';
            return `<div class="stack"><div>${acct}</div><div>${net}</div></div>`;
        }

        // 「最近登录」列：时间一行、登录 IP 一行（IP 弱化显示）。
        function accountLoginCell(a) {
            const time = a.last_login_at ? esc(fmtTime(a.last_login_at)) : '-';
            const ip = a.last_login_ip ? esc(a.last_login_ip) : '-';
            return `<div class="stack"><div>${time}</div><div class="muted">${ip}</div></div>`;
        }

        // 「帐号」列：账号名一行，绑定的 QQ 号一行（弱化）。
        //
        // 为什么不单开第 8 列：7 列是定好的版式，再加一列会把表格挤到横向滚动；
        // QQ 号是"这个账号的附加属性"，跟在账号名下面最自然
        //（与「最近登录」的时间 + IP 两行式同一处理）。
        function accountNameCell(a) {
            const name = esc(a.name);
            if (!a.qq_number) return name;
            return `<div class="stack"><div>${name}</div>` +
                `<div class="muted" title="该账号绑定的 QQ 号，可用于登录">QQ ${esc(a.qq_number)}</div></div>`;
        }

        async function loadAccounts(page) {
            accountPage = Math.max(1, page || 1);
            const keyword = document.getElementById('accountKeyword').value;
            const data = await api(`/api/admin/accounts?keyword=${encodeURIComponent(keyword)}&page=${accountPage}&page_size=${accountPageSize}`);
            if (!data) return;
            const tbody = document.getElementById('accountTable');
            tbody.innerHTML = '';
            (data.accounts || []).forEach(a => {
                // 操作列：查看角色 | 改密 | 解绑设备 | 封禁 | 删除。
                // 「解锁」只在账号当前处于锁定状态时才出现（安南定的口径）。
                // 已封禁的账号把「封禁」换成「解封」占同一格 —— 否则这个列表里
                // 点了封禁就再也没有解封的入口，得绕去「封禁管理」页。
                const banBtn = a.banned
                    ? `<button class="btn btn-sm btn-success" data-act="unban" data-account="${escAttr(a.name)}">解封</button>`
                    : `<button class="btn btn-sm btn-danger" data-act="ban" data-account="${escAttr(a.name)}">封禁</button>`;
                // 「解绑QQ」只在真的绑过 QQ 时才出现 —— 没绑的账号多一个永远点不动的
                // 按钮，只会让操作列更挤。
                const qqBtn = a.qq_number
                    ? `<button class="btn btn-sm" data-act="unbindqq" data-account="${escAttr(a.name)}" title="解除该账号与 QQ ${escAttr(a.qq_number)} 的绑定">解绑QQ</button>`
                    : '';
                tbody.innerHTML += `<tr data-account-row="${escAttr(a.name)}">
                    <td>${accountNameCell(a)}</td>
                    <td>${esc(a.m_id)}</td>
                    <td>${esc(a.cera)}</td>
                    <td>${accountCreatedCell(a)}</td>
                    <td>${accountLoginCell(a)}</td>
                    <td>${accountStatusCell(a)}</td>
                    <td class="td-actions">
                        <button class="btn btn-sm" data-act="roles" data-account="${escAttr(a.name)}">查看角色</button>
                        <button class="btn btn-sm" data-act="pwd" data-account="${escAttr(a.name)}">改密</button>
                        <button class="btn btn-sm" data-act="device" data-account="${escAttr(a.name)}">解绑设备</button>
                        ${qqBtn}
                        ${banBtn}
                        <button class="btn btn-sm btn-danger" data-act="del" data-account="${escAttr(a.name)}">删除</button>
                        ${a.locked ? `<button class="btn btn-sm" data-act="unlock" data-account="${escAttr(a.name)}">解锁</button>` : ''}
                    </td>
                </tr>`;
            });
            bindRowActions(tbody, 'data-act', {
                roles: (el) => toggleAccountRoles(el.dataset.account, el),
                pwd: (el) => resetPassword(el.dataset.account),
                device: (el) => resetDevice(el.dataset.account),
                unbindqq: (el) => unbindQQ(el.dataset.account),
                ban: (el) => banAccountFromList(el.dataset.account),
                unban: (el) => unbanAccountFromList(el.dataset.account),
                del: (el) => deleteAccount(el.dataset.account),
                unlock: (el) => unlockAccount(el.dataset.account)
            });

            const total = data.total || 0;
            const pageSize = data.page_size || accountPageSize;
            const maxPage = Math.max(1, Math.ceil(total / pageSize));
            setText('accountPageInfo', `第 ${accountPage} / ${maxPage} 页，共 ${total} 个账号　`);
            document.getElementById('accountPrev').disabled = accountPage <= 1;
            document.getElementById('accountNext').disabled = accountPage >= maxPage;
        }

        async function syncAccounts() {
            const data = await api('/api/admin/sync-game-accounts', 'POST');
            if (data) {
                alert(data.message || '同步完成');
                loadAccounts(accountPage);
            }
        }

        async function resetPassword(account) {
            // 明文输入两次，前端确认一致后提交明文，由服务端计算 MD5
            //（历史版本要求管理员自己算 32 位 MD5，谁都不会算）。
            const pwd = prompt(`重置「${account}」的密码。\n请输入新密码（6-32 位）：`);
            if (pwd === null) return;
            if (pwd.length < 6 || pwd.length > 32) { alert('密码长度需为 6-32 位'); return; }
            const pwd2 = prompt('请再次输入新密码确认：');
            if (pwd2 === null) return;
            if (pwd !== pwd2) { alert('两次输入的密码不一致'); return; }
            const data = await api('/api/admin/reset-password', 'POST', { account, newPassword: pwd });
            if (data) alert(data.message || (data.ok ? '重置成功' : '重置失败'));
        }

        async function resetDevice(account) {
            if (!confirm(`解除「${account}」的设备绑定？该账号在线会话会被断开。`)) return;
            const data = await api('/api/admin/reset-device', 'POST', { account });
            if (data) alert(data.message || (data.ok ? '解绑成功' : '解绑失败'));
        }

        // 解锁：清除连续登录失败造成的锁定。解锁后刷新列表，
        // 「解锁」按钮随 locked 变 false 自动消失（按钮只在锁定时渲染）。
        async function unlockAccount(account) {
            const data = await api('/api/admin/unlock', 'POST', { account });
            if (!data) return;
            alert(`账号「${account}」解锁完成${data.was_locked ? '' : '（该账号原本未被锁定）'}`);
            loadAccounts(accountPage);
        }

        // 解封：账号管理行内的「解封」（已封禁的账号会把「封禁」按钮换成它）。
        async function unbanAccountFromList(account) {
            if (!confirm(`解除账号「${account}」的封禁？解封后该账号可以重新登录。`)) return;
            const data = await api('/api/admin/unban', 'POST', { account });
            if (!data) return;
            alert(data.ok ? '已解封' : (data.message || '解封失败'));
            loadAccounts(accountPage);
        }

        // 解绑 QQ：账号管理行内的「解绑QQ」（只在真的绑过 QQ 时才出现）。
        //
        // 后台必须保留这个入口 —— 玩家 QQ 号被盗、换号、或那个 QQ 邮箱收不到信时，
        // 他自己解不了；没有这个按钮，他会永远卡在"登不进绑过 QQ 的账号"上。
        //
        // 与「解绑设备」是两件事：那个清的是设备绑定，这个解的是 QQ 号 ↔ 账号的关系。
        async function unbindQQ(account) {
            if (!confirm(`解除账号「${account}」的 QQ 号绑定？\n\n` +
                `解除后该 QQ 号不能再用于登录此账号，账号、密码、角色、点券都不受影响。`)) return;
            const data = await api('/api/admin/qq/unbind', 'POST', { account });
            if (!data) return;
            alert(data.ok ? (data.message || '已解除绑定') : (data.message || '解绑失败'));
            loadAccounts(accountPage);
        }

        // 删除单个账号：先 dryRun 预演拿统计，管理员确认后再真删。
        async function deleteAccount(account) {
            const pre = await api('/api/admin/delete-account', 'POST', { account, dryRun: true });
            if (!pre) return;
            if (!pre.preview) { alert(pre.message || '预演失败'); return; }
            const p = pre.preview;
            if (pre.would_skip || p.game_roles > 0) {
                alert(`账号「${account}」名下还有 ${p.game_roles} 个角色，无法删除。\n请先在游戏内删除角色后再试。`);
                return;
            }
            const lines = [
                `确认永久删除账号「${account}」？`,
                '',
                `m_id：${p.m_id}`,
                `点券：${p.cera}`,
                `设备历史：${p.device_history} 条（将被清理）`,
                `封禁记录：${p.banned ? '有（将被清理）' : '无'}`,
                `游戏库账号：${p.game_configured ? (p.game_account ? '有（将一并删除）' : '无') : '未配置'}`,
                `审计流水：${p.bonus_logs} 条奖励 / ${p.anticheat_rows} 条反作弊（默认保留）`,
                '',
                '删除后该账号无法再登录，且不可撤销。'
            ];
            if (!confirm(lines.join('\n'))) return;

            const data = await api('/api/admin/delete-account', 'POST', { account });
            if (!data) return;
            alert(data.message || (data.ok ? '删除成功' : '删除失败'));
            if (data.ok) loadAccounts(accountPage);
        }

        // 查角色：挂在账号行下面内联展开（不再弹窗）。
        //
        // 用「行下插一个详情行」而不是模态框的原因：管理员查角色往往是为了
        // 拿角色 ID 去发道具、或核对某个账号的角色，展开后账号信息仍在视野里；
        // 模态框会盖住账号列表，多账号对比时要反复开关。
        //
        // 再点一次同一按钮即收起。详情行带 data-role-detail 标记，
        // 重新查询/翻页会把整个 tbody 重建，旧详情行自然消失，不会残留。
        async function toggleAccountRoles(account, btn) {
            const row = btn.closest('tr');
            if (!row) return;

            // 已展开 → 收起
            const next = row.nextElementSibling;
            if (next && next.hasAttribute('data-role-detail') && next.dataset.account === account) {
                next.remove();
                btn.textContent = '查看角色';
                return;
            }

            const colspan = row.children.length;
            const detail = document.createElement('tr');
            detail.setAttribute('data-role-detail', '1');
            detail.dataset.account = account;
            detail.innerHTML = `<td colspan="${colspan}" class="muted">正在查询角色…</td>`;
            row.after(detail);

            btn.disabled = true;
            const original = btn.textContent;
            btn.textContent = '查询中…';

            const data = await api(`/api/admin/roles?account=${encodeURIComponent(account)}`);

            btn.disabled = false;
            btn.textContent = original;

            // 期间可能翻页/刷新过，行已不在文档里 → 别再写回
            if (!detail.isConnected) return;

            // 后端错误如实展示（ok=false + error），别吞成"没有查到角色"
            if (!data || data.ok === false) {
                const msg = (data && data.error) || '未知错误';
                detail.innerHTML = `<td colspan="${colspan}"><div class="alert alert-error">查询失败：${esc(msg)}</div></td>`;
                return;
            }

            const roles = data.roles || [];
            if (roles.length === 0) {
                detail.innerHTML = `<td colspan="${colspan}" class="muted">该账号没有查到角色（游戏库中无 m_id 关联记录，或游戏库未配置）</td>`;
                return;
            }

            // 发放道具的输入项只有一份（物品ID / 数量 / 类型），就在这张表的上面。
            // 单角色发放 = 只勾中那一行再点同一个按钮，不另开一套 prompt ——
            // 两套输入就会有两套校验，"单个能发、批量发不出去"这类不一致随之而来。
            detail.innerHTML = `<td colspan="${colspan}">
                <div style="padding:6px 0;">
                    <b>账号「${esc(account)}」的角色（共 ${roles.length} 个）</b>
                </div>
                <div class="role-toolbar">
                    <span class="muted">发放道具：</span>
                    <input type="number" min="1" class="item-id role-item-id" placeholder="物品ID">
                    <input type="number" min="1" class="role-count" placeholder="数量" value="1">
                    <select class="role-kind">${BC_KIND_OPTIONS.map(([v, l]) => `<option value="${v}">${esc(l)}</option>`).join('')}</select>
                    <button class="btn btn-sm" data-act="grant-selected">发放给勾选的 <b class="role-sel">0</b> 个角色</button>
                    <span class="muted">勾中多个角色可一次发放；点行尾「发放」= 只勾这一行</span>
                </div>
                <div class="grant-result"></div>
                <table>
                    <thead><tr>
                        <th style="width: 36px;"><input type="checkbox" class="role-all" onchange="toggleAllRoles(this)" title="全选 / 全不选"></th>
                        <th>角色ID</th><th>角色名</th><th>等级</th><th>职业</th><th>经验</th><th>操作</th>
                    </tr></thead>
                    <tbody>${roles.map(roleRowHtml).join('')}</tbody>
                </table>
            </td>`;

            bindRowActions(detail, 'data-act', {
                grant: (el) => selectSingleRole(el),
                'grant-selected': (el) => grantItemsToSelected(el)
            });
        }

        // 角色行：后端 RoleInfo 的 json 键是小写（character_id/name/level/job/grow_type/job_name/exp），
        // 但历史上也出现过 PascalCase，两种都认，免得改后端时静默变 '-'。
        //
        // 「职业」列优先用后端的 job_name —— 那是网关按 Script.pvf 的 character/*.chr
        // 解析出来的中文名（转职/觉醒优先，见 _jobdump）。万一没带出来，退回
        // 「职业 <job 数字>」，不显示空白（空白会被当成"查询出错"）。
        function roleRowHtml(r) {
            const pick = (a, b) => (r[a] !== undefined && r[a] !== null) ? r[a] : r[b];
            const name = pick('name', 'Name');
            const level = pick('level', 'Level');
            const jobName = pick('job_name', 'JobName');
            const jobId = pick('job', 'Job');
            const exp = pick('exp', 'Exp');
            const id = pick('character_id', 'CharacterId');
            const cell = (v) => esc((v === undefined || v === null || v === '') ? '-' : v);
            const jobCell = jobName
                ? esc(jobName)
                : ((jobId === undefined || jobId === null) ? '-' : '职业 ' + esc(jobId));
            return `<tr>
                <td><input type="checkbox" class="role-chk" value="${escAttr(id)}" onchange="updateRoleSelection(this)"></td>
                <td>${cell(id)}</td>
                <td>${cell(name)}</td>
                <td>${cell(level)}</td>
                <td>${jobCell}</td>
                <td>${cell(exp)}</td>
                <td><button class="btn btn-sm" data-act="grant" data-cid="${escAttr(id)}">发放</button></td>
            </tr>`;
        }

        // ── 角色勾选 ──
        // 全部在展开行（[data-role-detail]）范围内查，不用元素 id ——
        // 同一页可以同时展开多个账号，用 id 会互相打架。

        // 单角色发放：只勾中这一行，然后把焦点送到物品ID 输入框。
        function selectSingleRole(el) {
            const detail = el.closest('[data-role-detail]');
            const tr = el.closest('tr');
            if (!detail || !tr) return;
            const mine = tr.querySelector('.role-chk');
            detail.querySelectorAll('.role-chk').forEach(c => { c.checked = (c === mine); });
            syncRoleSelection(detail);
            const input = detail.querySelector('.role-item-id');
            if (input) input.focus();
        }

        function toggleAllRoles(el) {
            const detail = el.closest('[data-role-detail]');
            if (!detail) return;
            detail.querySelectorAll('.role-chk').forEach(c => { c.checked = el.checked; });
            syncRoleSelection(detail);
        }

        function updateRoleSelection(el) {
            const detail = el.closest('[data-role-detail]');
            if (detail) syncRoleSelection(detail);
        }

        // 同步「已勾选 N 个」以及表头全选框的 选中 / 半选 状态。
        function syncRoleSelection(detail) {
            const all = detail.querySelectorAll('.role-chk');
            const checked = detail.querySelectorAll('.role-chk:checked');
            const label = detail.querySelector('.role-sel');
            if (label) label.textContent = checked.length;
            const box = detail.querySelector('.role-all');
            if (box) {
                box.checked = all.length > 0 && checked.length === all.length;
                box.indeterminate = checked.length > 0 && checked.length < all.length;
            }
        }

        // 发放道具：把一件物品投递到所有勾选的角色（走邮件）。
        //
        // kind 默认 3 = 服务端 ItemCore 的「材料 / 普通」。邮件一旦写进游戏库
        // 就撤不回来，所以发送前把「发给谁 / 发什么 / 发多少 / 什么类型」摆清楚，
        // 要求再确认一次。后端按角色逐个投递，失败的会原样带回来。
        async function grantItemsToSelected(btn) {
            const detail = btn.closest('[data-role-detail]');
            if (!detail) return;

            const ids = Array.from(detail.querySelectorAll('.role-chk:checked'))
                .map(c => parseInt(c.value, 10))
                .filter(n => n > 0);
            if (ids.length === 0) { alert('请先勾选要发放的角色'); return; }

            const itemEl = detail.querySelector('.role-item-id');
            const countEl = detail.querySelector('.role-count');
            const kindEl = detail.querySelector('.role-kind');
            const itemId = parseInt(itemEl.value, 10);
            const count = parseInt(countEl.value, 10);
            const kind = parseInt(kindEl.value, 10);
            if (!(itemId > 0)) { alert('请输入有效的物品 ID'); itemEl.focus(); return; }
            if (!(count > 0)) { alert('请输入有效的数量'); countEl.focus(); return; }

            const kindLabel = (BC_KIND_OPTIONS.find(([v]) => v === String(kind)) || [null, kind])[1];
            const lines = [
                `向 ${ids.length} 个角色发放道具？`,
                '',
                `物品ID：${itemId}`,
                `数量：${count}`,
                `类型：${kindLabel}`,
                `角色ID：${ids.join(', ')}`,
                '',
                '物品会进角色邮箱，发放后无法撤回。'
            ];
            if (!confirm(lines.join('\n'))) return;

            btn.disabled = true;
            const data = await api('/api/admin/send-items', 'POST', {
                characterIds: ids,
                items: [{ item_template_id: itemId, count, kind }]
            });
            btn.disabled = false;
            if (!data) return;

            const failed = data.failed || [];
            const failText = failed.length
                ? '　失败：' + failed.map(f => `${f.character_id}（${f.error}）`).join('；')
                : '';
            const box = detail.querySelector('.grant-result');
            if (data.ok) {
                const text = `${data.message || '已投递'}（共 ${data.total || ids.length} 个目标）${failText}`;
                if (box) box.innerHTML = `<div class="alert alert-success">${esc(text)}</div>`;
            } else {
                const text = `${data.message || '投递失败'}${failText}`;
                if (box) box.innerHTML = `<div class="alert alert-error">${esc(text)}</div>`;
            }
        }

        // 批量重置全部账号密码。
        //
        // 明文输入两次（前端先比一致性），MD5 由服务端算 —— 历史版本要求管理员
        // 自己算 32 位 MD5，没人算得出来。后端另外保留了「直接给 MD5」的入口给脚本调用。
        async function resetAllPasswords(dryRun) {
            const pwd = document.getElementById('allPwd1').value;
            const pwd2 = document.getElementById('allPwd2').value;
            if (pwd.length < 6 || pwd.length > 32) { alert('密码长度需为 6-32 位'); return; }
            if (pwd !== pwd2) { alert('两次输入的密码不一致'); return; }

            if (!dryRun) {
                const lines = [
                    '确认把所有账号的密码重置为同一套？',
                    '',
                    '影响范围：全部账号（含离线玩家）',
                    '后果：改完全体玩家需要用新密码重新登录，不可撤销。'
                ];
                if (!confirm(lines.join('\n'))) return;
            }

            const data = await api('/api/admin/reset-all-passwords', 'POST', { newPassword: pwd, dryRun });
            if (!data) return;
            if (data.ok && !dryRun) {
                // 真执行成功后清空输入框，避免密码留在页面上被旁人看到
                document.getElementById('allPwd1').value = '';
                document.getElementById('allPwd2').value = '';
            }
            showResult('allPwdResult', data.ok ? 'success' : 'error',
                `${data.message || ''}　总数 ${data.total}，已更新 ${data.updated}，失败 ${data.failed}`);
        }

        // ==================== 封禁管理 ====================

        async function loadBans() {
            const data = await api('/api/admin/bans');
            if (!data) return;
            const tbody = document.getElementById('banTable');
            tbody.innerHTML = '';
            (data.rows || []).forEach(b => {
                tbody.innerHTML += `<tr>
                    <td>${esc(b.name)}</td>
                    <td>${esc(b.reason)}</td>
                    <td>${esc(fmtTime(b.banned_at))}</td>
                    <td><button class="btn btn-sm" data-act="unban" data-account="${escAttr(b.name)}">解封</button></td>
                </tr>`;
            });
            bindRowActions(tbody, 'data-act', {
                unban: (el) => unbanAccount(el.dataset.account)
            });
        }

        async function banAccount() {
            const account = document.getElementById('banAccount').value;
            const reason = document.getElementById('banReason').value;
            if (!account) { alert('请输入账号'); return; }
            await api('/api/admin/ban', 'POST', { account, reason });
            document.getElementById('banAccount').value = '';
            document.getElementById('banReason').value = '';
            loadBans();
        }

        async function unbanAccount(account) {
            await api('/api/admin/unban', 'POST', { account });
            loadBans();
        }

        // 账号管理行内的封禁：封禁即踢下线（后端 handleAdminBan 已联动）。
        //
        // 两次确认：先填理由，再把「账号 + 理由 + 后果」摆出来让管理员点第二次。
        // 封禁会直接踢掉在线玩家，一个 prompt 回车就生效太容易误伤。
        async function banAccountFromList(account) {
            const reason = prompt(`封禁账号「${account}」的原因：`, '违规');
            if (reason === null) return;
            const trimmed = reason.trim() || '未填写';
            const lines = [
                `确认封禁账号「${account}」？`,
                '',
                `原因：${trimmed}`,
                '',
                '封禁后立即断开该账号的在线会话，且无法再登录。'
            ];
            if (!confirm(lines.join('\n'))) return;

            const data = await api('/api/admin/ban', 'POST', { account, reason: trimmed });
            if (!data) return;
            alert(data.ok ? `已封禁（踢下线 ${data.kicked ?? 0} 个在线会话）` : (data.message || '封禁失败'));
            loadAccounts(accountPage);
        }

        // ==================== 全服发放 ====================

        // kind 的合法值 = 服务端 ItemCore 的 Kind 常量（Game/Inventory/Models/ItemCore.cs）。
        const BC_KIND_OPTIONS = [
            ['3', '材料 / 普通 (3，默认)'],
            ['1', '装备 (1)'],
            ['2', '消耗品 (2)'],
            ['4', '任务物品 (4)'],
            ['5', '宠物 (5)'],
            ['6', '宠物装备 (6)'],
            ['7', '宠物消耗品 (7)'],
            ['8', '时装 (8)'],
            ['9', '时装徽章 (9)'],
        ];

        function bcKindSelect(val) {
            const v = (val === undefined || val === null || val === '') ? '3' : String(val);
            let opts = BC_KIND_OPTIONS.map(([value, label]) =>
                `<option value="${value}"${v === value ? ' selected' : ''}>${label}</option>`).join('');
            if (!BC_KIND_OPTIONS.some(([value]) => value === v))
                opts += `<option value="${escAttr(v)}" selected>其他 (${escAttr(v)})</option>`;
            return `<select class="bc-kind" style="width:100%;margin:0;">${opts}</select>`;
        }

        // item_type 目前服务端领取链路不读它（信息性字段），合法值只有默认 0；
        // 其余值走"手动输入"，避免自由文本误输。
        function bcItemTypeSelect(val) {
            const v = (val === undefined || val === null || val === '') ? '0' : String(val);
            let opts = '';
            if (v === '0') {
                opts = `<option value="0" selected>默认 (0)</option>`;
            } else {
                opts = `<option value="${escAttr(v)}" selected>当前 (${escAttr(v)})</option><option value="0">默认 (0)</option>`;
            }
            opts += `<option value="__custom__">手动输入…</option>`;
            return `<select class="bc-itemtype" style="width:100%;margin:0;">${opts}</select>`;
        }

        function bcItemRow(tpl, count, kind, itemType) {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td><input type="text" class="bc-tpl" value="${escAttr(tpl || '')}" style="width:100%;margin:0;"></td>
                <td><input type="text" class="bc-count" value="${escAttr(count === undefined ? 1 : count)}" style="width:100%;margin:0;"></td>
                <td>${bcKindSelect(kind)}</td>
                <td>${bcItemTypeSelect(itemType)}</td>
                <td><button class="btn btn-danger btn-sm" data-act="delfile">删除</button></td>`;
            tr.querySelector('[data-act="delfile"]').addEventListener('click', () => tr.remove());
            const itSel = tr.querySelector('.bc-itemtype');
            itSel.addEventListener('change', (e) => {
                if (e.target.value !== '__custom__') return;
                const n = parseInt(prompt('请输入 item_type 数值（非负整数）：', '0'), 10);
                if (isNaN(n) || n < 0) { e.target.value = '0'; return; }
                const opt = document.createElement('option');
                opt.value = String(n);
                opt.textContent = `自定义 (${n})`;
                opt.selected = true;
                e.target.insertBefore(opt, e.target.querySelector('option[value="__custom__"]'));
            });
            return tr;
        }

        function addBcItem(tpl, count, kind, itemType) {
            document.getElementById('bcItemTable').appendChild(bcItemRow(tpl, count, kind, itemType));
        }

        function collectBcItems() {
            const items = [];
            document.querySelectorAll('#bcItemTable tr').forEach(tr => {
                const tpl = parseInt(tr.querySelector('.bc-tpl').value, 10);
                if (!tpl || tpl <= 0) return;
                const item = {
                    item_template_id: tpl,
                    count: parseInt(tr.querySelector('.bc-count').value, 10) || 1
                };
                const kind = tr.querySelector('.bc-kind').value.trim();
                const itemType = tr.querySelector('.bc-itemtype').value.trim();
                if (kind !== '') item.kind = parseInt(kind, 10);
                if (itemType !== '') item.item_type = parseInt(itemType, 10);
                items.push(item);
            });
            return items;
        }

        async function submitBroadcast() {
            const items = collectBcItems();
            if (items.length === 0) { showResult('bcResult', 'error', '至少需要一个有效物品 ID'); return; }
            const body = { items };
            const charId = document.getElementById('bcCharId').value.trim();
            const accId = document.getElementById('bcAccId').value.trim();
            const expire = document.getElementById('bcExpire').value.trim();
            const subject = document.getElementById('bcSubject').value.trim();
            const text = document.getElementById('bcBody').value.trim();
            if (charId) body.target_character_id = parseInt(charId, 10);
            if (accId) body.target_account_id = parseInt(accId, 10);
            if (expire) body.expire_hours = parseInt(expire, 10);
            if (subject) body.subject = subject;
            if (text) body.body = text;

            const scope = charId ? `角色 ${charId}` : (accId ? `账号 ${accId}` : '全服');
            if (!confirm(`确认向【${scope}】发放 ${items.length} 种道具？`)) return;

            const data = await api('/api/admin/broadcast', 'POST', body);
            if (!data) return;
            const ok = data.success !== false && data.ok !== false;
            showResult('bcResult', ok ? 'success' : 'error',
                data.message || (ok ? '发放完成' : '发放失败'));
        }

        // ==================== 客户端校验 ====================

        let integritySnapshot = { white: [], black: [], allowed: [] };

        async function loadIntegrity() {
            const data = await api('/api/admin/integrity');
            if (!data) return;
            integritySnapshot = {
                white: data.white || [],
                black: data.black || [],
                allowed: data.allowed || []
            };
            setText('integrityMeta', `策略版本 ${data.revision}，更新时间 ${data.updated_at || '-'}`);
            renderFingerprintTable('whiteTable', 'white', integritySnapshot.white);
            renderFingerprintTable('blackTable', 'black', integritySnapshot.black);
            renderAllowTable(integritySnapshot.allowed);
            loadPvfInfo();
        }

        function renderFingerprintTable(tbodyId, kind, entries) {
            const tbody = document.getElementById(tbodyId);
            tbody.innerHTML = '';
            if (entries.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" class="muted">暂无条目</td></tr>';
                return;
            }
            entries.forEach(e => {
                tbody.innerHTML += `<tr>
                    <td>${esc(e.file)}</td>
                    <td>${esc(e.algo)}</td>
                    <td title="${escAttr(e.hash)}">${esc(truncHash(e.hash))}</td>
                    <td>${esc(fmtSize(e.size))}</td>
                    <td><button class="btn btn-danger btn-sm" data-act="del"
                        data-kind="${escAttr(kind)}"
                        data-file="${escAttr(e.file)}"
                        data-hash="${escAttr(e.hash)}">删除</button></td>
                </tr>`;
            });
            bindRowActions(tbody, 'data-act', {
                del: (el) => removeFingerprint(el.dataset.kind, el.dataset.file, el.dataset.hash)
            });
        }

        function renderAllowTable(list) {
            const tbody = document.getElementById('allowTable');
            tbody.innerHTML = '';
            if (!list || list.length === 0) {
                tbody.innerHTML = '<tr><td colspan="2" class="muted">暂无条目</td></tr>';
                return;
            }
            list.forEach(name => {
                tbody.innerHTML += `<tr>
                    <td>${esc(name)}</td>
                    <td><button class="btn btn-danger btn-sm" data-act="del" data-name="${escAttr(name)}">移除</button></td>
                </tr>`;
            });
            bindRowActions(tbody, 'data-act', {
                del: (el) => removeAllowed(el.dataset.name)
            });
        }

        async function uploadIntegrity(kind) {
            const input = document.getElementById(kind === 'white' ? 'whiteFiles' : 'blackFiles');
            if (!input.files || input.files.length === 0) {
                showResult('integrityResult', 'error', '请先选择文件');
                return;
            }
            const fd = new FormData();
            for (const f of input.files) fd.append('files', f, f.name);

            showResult('integrityResult', 'success', `正在上传 ${input.files.length} 个文件并计算指纹…`);
            const data = await upload(`/api/admin/integrity/upload?kind=${encodeURIComponent(kind)}`, fd);
            if (!data) return;
            input.value = '';
            if (data.ok) {
                const errs = (data.errors || []).length;
                showResult('integrityResult', 'success',
                    `已加入${kind === 'white' ? '白' : '黑'}名单：新增 ${data.added} / 共 ${data.total_files} 个文件`
                    + (errs ? `，${errs} 个失败` : ''));
                loadIntegrity();
            } else {
                showResult('integrityResult', 'error', data.message || data.error || '上传失败');
            }
        }

        async function manualAdd() {
            const kind = document.getElementById('manualKind').value;
            const file = document.getElementById('manualFile').value.trim();
            const hash = document.getElementById('manualHash').value.trim();
            if (!file || !hash) { showResult('integrityResult', 'error', '文件名与指纹都要填'); return; }
            const data = await api('/api/admin/integrity/add', 'POST', {
                kind,
                entries: [{ file, hash, algo: 'SHA-256' }]
            });
            if (!data) return;
            if (data.ok) {
                showResult('integrityResult', 'success', `已添加，${data.added} / ${data.total} 条生效`);
                document.getElementById('manualFile').value = '';
                document.getElementById('manualHash').value = '';
                loadIntegrity();
            } else {
                showResult('integrityResult', 'error', data.message || '添加失败');
            }
        }

        async function removeFingerprint(kind, file, hash) {
            if (!confirm(`从${kind === 'white' ? '白' : '黑'}名单移除「${file}」？`)) return;
            const data = await api('/api/admin/integrity/remove', 'POST', { kind, file, hash });
            if (!data) return;
            if (data.ok) loadIntegrity();
            else showResult('integrityResult', 'error', data.message || '未找到该条目');
        }

        async function addAllowed() {
            const raw = document.getElementById('allowItem').value.trim();
            if (!raw) return;
            const names = raw.split(/[,，\s]+/).map(s => s.trim()).filter(s => s);
            const data = await api('/api/admin/integrity/allow', 'POST', { names });
            if (!data) return;
            const rejected = data.rejected || [];
            showResult('integrityResult', rejected.length ? 'error' : 'success',
                `已允许 ${data.added} 个模块，当前共 ${data.allowed_count} 个`
                + (rejected.length ? `；被拒绝：${rejected.join(', ')}` : ''));
            document.getElementById('allowItem').value = '';
            loadIntegrity();
        }

        async function removeAllowed(name) {
            if (!confirm(`移除允许模块「${name}」？`)) return;
            const data = await api('/api/admin/integrity/remove', 'POST', { kind: 'allow', file: name });
            if (!data) return;
            if (data.ok) loadIntegrity();
            else showResult('integrityResult', 'error', '未找到该模块');
        }

        async function loadPvfInfo() {
            const data = await api('/api/pvf/info');
            if (!data) return;
            const box = document.getElementById('pvfInfo');
            box.className = 'pre';
            box.innerText =
                `来源模式　${data.mode || '-'}\n` +
                `指纹算法　${data.algo || '-'}\n` +
                `指纹　　　${data.hash || '-'}\n` +
                `文件大小　${fmtSize(data.size)}\n` +
                `文件路径　${data.path || '-'}\n` +
                `修改时间　${data.modified_utc || '-'}`;
        }

        async function refreshPvfCache() {
            const data = await api('/api/admin/refresh-pvf', 'POST', {});
            if (!data) return;
            showResult('pvfResult', data.ok ? 'success' : 'error',
                data.ok ? '缓存已重算' : (data.error || '重算失败'));
            loadPvfInfo();
        }

        async function unregisterPvf() {
            if (!confirm('注销已注册的 PVF 指纹？客户端将回退到文件模式校验。')) return;
            const data = await api('/api/admin/pvf/unregister', 'POST', {});
            if (!data) return;
            showResult('pvfResult', data.ok ? 'success' : 'error',
                data.ok ? '已注销' : (data.error || '注销失败'));
            loadPvfInfo();
        }

        async function uploadPvf() {
            const input = document.getElementById('pvfFile');
            if (!input.files || input.files.length === 0) { showResult('pvfResult', 'error', '请先选择 PVF 文件'); return; }
            if (!confirm('确认用该文件替换服务端 PVF？此操作会覆盖现有文件。')) return;
            const fd = new FormData();
            fd.append('file', input.files[0], input.files[0].name);
            showResult('pvfResult', 'success', '正在上传，大文件耗时较长请稍候…');
            const data = await upload('/api/admin/upload-pvf', fd);
            if (!data) return;
            input.value = '';
            if (data.ok) {
                showResult('pvfResult', 'success', `替换完成，新指纹 ${truncHash(data.hash)}（${fmtSize(data.size)}）`);
                loadPvfInfo();
                loadIntegrity();
            } else {
                showResult('pvfResult', 'error', data.message || data.error || '替换失败');
            }
        }

        async function registerPvf() {
            const file = document.getElementById('regFile').value.trim();
            const hash = document.getElementById('regHash').value.trim();
            const size = document.getElementById('regSize').value.trim();
            if (!hash) { showResult('pvfResult', 'error', '指纹必填'); return; }
            const body = { hash, algo: 'SHA-256', file };
            if (size) body.size = parseInt(size, 10);
            const data = await api('/api/admin/pvf/register', 'POST', body);
            if (!data) return;
            showResult('pvfResult', data.ok ? 'success' : 'error',
                data.ok ? `注册成功，指纹 ${truncHash(data.hash)}` : (data.message || data.error || '注册失败'));
            if (data.ok) loadPvfInfo();
        }

        // ==================== 服务端管理 ====================

        // fmtDuration 把秒数说成人话 —— 运行时长是给人看的，
        // 不该在界面上出现 "已运行 184320 秒"。
        function fmtDuration(sec) {
            if (!sec || sec < 0) return '-';
            const d = Math.floor(sec / 86400);
            const h = Math.floor((sec % 86400) / 3600);
            const m = Math.floor((sec % 3600) / 60);
            const s = Math.floor(sec % 60);
            if (d > 0) return `${d} 天 ${h} 小时 ${m} 分`;
            if (h > 0) return `${h} 小时 ${m} 分`;
            if (m > 0) return `${m} 分 ${s} 秒`;
            return `${s} 秒`;
        }

        // fmtBytes 内存 / 文件大小。后端给的一律是字节。
        function fmtBytes(n) {
            if (!n || n < 0) return '-';
            const units = ['B', 'KB', 'MB', 'GB', 'TB'];
            let v = n, i = 0;
            while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
            return (i === 0 ? v : v.toFixed(1)) + ' ' + units[i];
        }

        // procStatsLines 拼「启动时间 / 已运行 / 占用内存」三行。
        //
        // 后端读不到 /proc 时**不给这几个字段**，这里统一显示 '-' ——
        // 宁可见到短横线，也不要显示一个像是"服务挂了"的 0 B。
        function procStatsLines(st) {
            const started = st.started_at ? new Date(st.started_at * 1000).toLocaleString() : '-';
            return `启动时间　${started}\n` +
                `已运行　　${fmtDuration(st.uptime_seconds)}\n` +
                `占用内存　${fmtBytes(st.rss_bytes)}`;
        }

        async function loadServerStatus() {
            const data = await api('/api/admin/server/status');
            if (!data) return;
            setText('serverControlFlag', data.control_enabled ? '（可远程控制）' : '（未开启远程控制）');
            const st = data.status || {};
            document.getElementById('serverStatus').innerText =
                `运行状态　${st.active || '-'} / ${st.sub_state || '-'}\n` +
                `进程 PID　${st.pid || '-'}\n` +
                procStatsLines(st) + '\n' +
                `启动命令　${st.exec_start || '-'}`;
        }

        async function serverControl(action) {
            const labels = { start: '启动', stop: '停止', restart: '重启' };
            if (!confirm(`确认${labels[action] || action}服务端？`)) return;
            const data = await api('/api/admin/server/control', 'POST', { action });
            if (data && data.ok === false) alert('操作失败：' + (data.error || '未知错误'));
            loadServerStatus();
        }

        async function loadServerLogs() {
            const key = document.getElementById('serverLogKey').value;
            const lines = document.getElementById('serverLogLines').value || '300';
            const data = await api(`/api/admin/server/logs?key=${encodeURIComponent(key)}&lines=${encodeURIComponent(lines)}`);
            if (!data) return;
            const box = document.getElementById('serverLogs');
            const r = data.result || {};
            // 后端 LogResult：{Error string, Lines []string}
            if (r.Error) {
                box.innerText = `读取失败：${r.Error}`;
            } else if (Array.isArray(r.Lines)) {
                box.innerText = r.Lines.length ? r.Lines.join('\n') : '（日志为空）';
            } else {
                box.innerText = JSON.stringify(r, null, 2);
            }
            box.scrollTop = box.scrollHeight;
        }

        async function doBackup() {
            showResult('backupResult', 'success', '正在备份，请稍候…（库较大时会在备份后收缩，可能需要几十秒）');
            const data = await api('/api/admin/server/backup', 'POST', {});
            if (!data) return;
            if (!data.ok) {
                showResult('backupResult', 'error', data.error || '备份失败');
                loadBackups();
                return;
            }
            // 备份成功后再补一句审计日志清理的结果：这一步失败不影响备份本身，
            // 但必须让操作者看到（否则"库没变小"会变成一个查不出原因的疑问）。
            const r = data.result || {};
            let msg = '备份完成';
            if (r.AuditPurgeError) {
                msg += `；审计日志清理告警：${r.AuditPurgeError}`;
                showResult('backupResult', 'error', msg);
            } else if (r.AuditPurgeSkipped) {
                msg += `；未清理审计日志（${r.AuditPurgeSkipped}）`;
                showResult('backupResult', 'success', msg);
            } else {
                msg += `；已清理审计日志 ${r.AuditPurgedRows || 0} 条，游戏库 `
                    + `${fmtSize(r.GameDbBytesBefore)} → ${fmtSize(r.GameDbBytesAfter)}`;
                showResult('backupResult', 'success', msg);
            }
            loadBackups();
        }

        async function loadBackups() {
            const data = await api('/api/admin/server/backups');
            if (!data) return;
            const tbody = document.getElementById('backupTable');
            tbody.innerHTML = '';

            // 后端现在返回结构化对象（name/path/size/modified_at），并覆盖
            // 游戏库/网关库 .db 与服务端 Script-*.pvf 三类。
            // 目录不存在或没权限时 items 为空且带 error，这里如实显示原因，
            // 免得只看到一个空表格不知道该去查什么。
            const items = data.items || [];
            const totalSize = items.reduce((s, it) => s + ((it && typeof it === 'object' && it.size) ? it.size : 0), 0);
            setText('backupDir', (data.directory || '') +
                (items.length ? `　共 ${items.length} 个文件、${fmtSize(totalSize)}` : '') +
                (data.error ? `　读取失败：${data.error}` : ''));

            if (items.length === 0) {
                tbody.innerHTML = `<tr><td colspan="3" class="muted">${data.error ? '无法读取备份目录' : '暂无备份'}</td></tr>`;
                return;
            }

            items.forEach(it => {
                // 兼容万一回退成字符串数组（旧后端）的情况
                if (typeof it === 'string') {
                    const name = it.split(/[\\/]/).pop() || it;
                    tbody.innerHTML += `<tr><td title="${escAttr(it)}">${esc(name)}</td><td>-</td><td>-</td></tr>`;
                    return;
                }
                const name = it.name || (it.path || '').split(/[\\/]/).pop() || '-';
                const t = it.modified_at;
                const time = typeof t === 'number' ? fmtTime(t) : (t || '-');
                tbody.innerHTML += `<tr>
                    <td title="${escAttr(it.path || name)}">${esc(name)}</td>
                    <td>${esc(fmtSize(it.size))}</td>
                    <td>${esc(time)}</td>
                </tr>`;
            });
        }

        async function replaceServerPvf() {
            const input = document.getElementById('serverPvfFile');
            if (!input.files || input.files.length === 0) { showResult('serverPvfResult', 'error', '请先选择 PVF 文件'); return; }
            if (!confirm('确认替换服务端 PVF 文件？')) return;
            const fd = new FormData();
            fd.append('file', input.files[0], input.files[0].name);
            showResult('serverPvfResult', 'success', '正在上传替换，请稍候…');
            const data = await upload('/api/admin/server/pvf', fd);
            if (!data) return;
            input.value = '';
            showResult('serverPvfResult', data.ok ? 'success' : 'error',
                data.ok ? '服务端 PVF 替换完成' : (data.error || '替换失败'));
        }

        function rbItemRow(item) {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td><input type="text" class="rb-id" value="${escAttr(item && item.item_id !== undefined ? item.item_id : '')}" style="width:100%;margin:0;"></td>
                <td><input type="text" class="rb-name" value="${escAttr(item && item.name !== undefined ? item.name : '')}" style="width:100%;margin:0;"></td>
                <td><input type="text" class="rb-count" value="${escAttr(item && item.count !== undefined ? item.count : 1)}" style="width:100%;margin:0;"></td>
                <td><input type="text" class="rb-kind" value="${escAttr(item && item.kind !== undefined ? item.kind : '')}" placeholder="默认3" style="width:100%;margin:0;"></td>
                <td><input type="text" class="rb-itemtype" value="${escAttr(item && item.item_type !== undefined ? item.item_type : '')}" placeholder="默认0" style="width:100%;margin:0;"></td>
                <td><button class="btn btn-danger btn-sm" data-act="del">删除</button></td>`;
            tr.querySelector('[data-act="del"]').addEventListener('click', () => tr.remove());
            return tr;
        }

        function addRbItem(item) {
            document.getElementById('rbItemTable').appendChild(rbItemRow(item));
        }

        async function loadRegisterBonus() {
            const data = await api('/api/admin/register-bonus/config');
            if (!data) return;
            const tbody = document.getElementById('rbItemTable');
            tbody.innerHTML = '';
            const cfg = data.config;
            if (!cfg) {
                setText('rbResult', '');
                document.getElementById('rbResult').innerHTML =
                    '<div class="alert alert-error">尚未配置注册奖励，填写后点击保存即可创建</div>';
                addRbItem(null);
                return;
            }
            document.getElementById('rbResult').innerHTML = '';
            document.getElementById('rbEnabled').checked = !!cfg.enabled;
            document.getElementById('rbCera').value = cfg.cera || 0;
            document.getElementById('rbTokenCera').value = cfg.token_cera || 0;
            document.getElementById('rbHappyTokenCera').value = cfg.happy_token_cera || 0;
            document.getElementById('rbGold').value = cfg.gold || 0;
            document.getElementById('rbTitle').value = cfg.title || '';
            document.getElementById('rbBody').value = cfg.body || '';
            document.getElementById('rbExpireHours').value = cfg.item_expire_hours || 0;
            document.getElementById('rbSplitCount').value = cfg.item_split_count || 0;
            document.getElementById('rbStackLimit').value = cfg.item_stack_limit || 0;
            document.getElementById('rbDeliverLimit').value = cfg.item_deliver_limit || 0;
            document.getElementById('rbAttachLimit').value = cfg.item_attachments_per_mail || 0;
            (cfg.items || []).forEach(it => addRbItem(it));
            if ((cfg.items || []).length === 0) addRbItem(null);
        }

        async function saveRegisterBonus() {
            const items = [];
            document.querySelectorAll('#rbItemTable tr').forEach(tr => {
                const id = parseInt(tr.querySelector('.rb-id').value, 10);
                if (!id || id <= 0) return;
                const item = {
                    item_id: id,
                    name: tr.querySelector('.rb-name').value.trim(),
                    count: parseInt(tr.querySelector('.rb-count').value, 10) || 1,
                    kind: parseInt(tr.querySelector('.rb-kind').value, 10) || 3,
                    item_type: parseInt(tr.querySelector('.rb-itemtype').value, 10) || 0
                };
                items.push(item);
            });
            const num = (id) => parseInt(document.getElementById(id).value, 10) || 0;
            const cfg = {
                enabled: document.getElementById('rbEnabled').checked,
                cera: num('rbCera'),
                token_cera: num('rbTokenCera'),
                happy_token_cera: num('rbHappyTokenCera'),
                gold: num('rbGold'),
                title: document.getElementById('rbTitle').value,
                body: document.getElementById('rbBody').value,
                item_expire_hours: num('rbExpireHours'),
                item_split_count: num('rbSplitCount'),
                item_stack_limit: num('rbStackLimit'),
                item_deliver_limit: num('rbDeliverLimit'),
                item_attachments_per_mail: num('rbAttachLimit'),
                items
            };
            const data = await api('/api/admin/register-bonus/config', 'POST', cfg);
            if (!data) return;
            showResult('rbResult', data.ok ? 'success' : 'error', data.message || (data.ok ? '保存成功' : '保存失败'));
        }

        let rbLogPage = 1;

        // ==================== 泡点设置（服务端管理页） ====================
        //
        // 读写的是网关运行目录下的 bonus.json。两个进程都能直接改这个文件，
        // 所以这里不需要走内部 API；泡点主循环每轮重读盘，保存即生效。
        async function loadBonusConfig() {
            const data = await api('/api/admin/bonus/config');
            if (!data) return;
            // 后端在文件缺失/JSON 损坏时会 ok:false 并带上 error ——
            // 这时必须如实提示，不能拿默认值糊过去（否则一保存就覆盖线上配置）。
            if (data.ok === false) {
                showResult('bonusResult', 'error', '读取失败：' + (data.error || '未知错误'));
                return;
            }
            const c = data.config || {};
            document.getElementById('bonusEnabled').checked = !!c.enabled;
            document.getElementById('bonusInterval').value = c.interval_seconds;
            document.getElementById('bonusAmount').value = c.amount_per_interval;
            setText('bonusPath', data.path || '');
        }

        async function saveBonusConfig() {
            const interval = parseInt(document.getElementById('bonusInterval').value, 10);
            const amount = parseInt(document.getElementById('bonusAmount').value, 10);
            // 前端先挡一道明显非法的输入，后端还会再校验一次（两侧都要）。
            if (!(interval >= 1 && interval <= 86400)) { alert('计费周期要在 1 ~ 86400 秒之间'); return; }
            if (!(amount >= 0 && amount <= 10000000)) { alert('每周期点券要在 0 ~ 10000000 之间'); return; }

            const cfg = {
                enabled: document.getElementById('bonusEnabled').checked,
                interval_seconds: interval,
                amount_per_interval: amount
            };
            const data = await api('/api/admin/bonus/config', 'POST', cfg);
            if (!data) return;
            if (data.ok === false) {
                showResult('bonusResult', 'error', '保存失败：' + (data.error || '未知错误'));
                return;
            }
            showResult('bonusResult', 'success', data.message || '已保存');
        }

        async function loadBonusLogs(page) {
            rbLogPage = Math.max(1, page || 1);
            const account = document.getElementById('rbLogAccount').value.trim();
            const type = document.getElementById('rbLogType').value.trim();
            const status = document.getElementById('rbLogStatus').value.trim();
            const qs = `account=${encodeURIComponent(account)}&reward_type=${encodeURIComponent(type)}` +
                       `&status=${encodeURIComponent(status)}&page=${rbLogPage}&page_size=20`;
            const data = await api('/api/admin/register-bonus/logs?' + qs);
            if (!data) return;
            const tbody = document.getElementById('rbLogTable');
            tbody.innerHTML = '';
            const rows = data.rows || [];
            if (rows.length === 0) {
                tbody.innerHTML = '<tr><td colspan="8" class="muted">暂无记录</td></tr>';
            }
            rows.forEach(r => {
                tbody.innerHTML += `<tr>
                    <td>${esc(r.account)}</td>
                    <td>${esc(r.character_name || r.character_id)}</td>
                    <td>${esc(r.reward_type)}</td>
                    <td>${esc(r.item_name || r.item_id)}</td>
                    <td>${esc(r.quantity)}</td>
                    <td>${esc(r.status)}</td>
                    <td>${esc(r.message)}</td>
                    <td>${esc(r.created_at)}</td>
                </tr>`;
            });
            const total = data.total || 0;
            const pageSize = data.page_size || 20;
            const maxPage = Math.max(1, Math.ceil(total / pageSize));
            setText('rbLogPageInfo', `第 ${rbLogPage} / ${maxPage} 页，共 ${total} 条　`);
        }

        // ==================== 活动管理（服务端管理页） ====================
        //
        // 写的是**游戏库**的 game_event_state / game_event_info_details。
        // 界面要老实交代两件事，否则操作者一定会踩：
        //   ① 生效时机 —— 开关即时生效，客户端活动列表要玩家重登才刷新；
        //   ② 文案被服务端覆盖 —— 骑士马战（2365）的文案由服务端硬编码，
        //      重启服务端就还原。这个"改了没报错、过几天自己变回去"的坑
        //      必须在保存那一刻就说出来，而不是等运营来问。

        let gameEventCache = [];
        let gameEventDefaultsMap = {};
        let gameEventEditingId = 0;

        // fmtUtc 游戏库时间列是 UTC 且不带时区后缀，浏览器会当本地时间
        // 显示（差 8 小时），所以要手工补 'Z'。
        function fmtUtcGame(s) {
            return s ? s + 'Z' : '-';
        }

        async function loadGameEvents() {
            const tbody = document.getElementById('gameEventTable');
            const data = await api('/api/admin/game-events');
            if (!data) return;

            if (!data.ok) {
                setText('gameEventMeta', '');
                setText('gameEventHint', '');
                tbody.innerHTML = `<tr><td colspan="6" class="muted">${esc(data.message || '读取失败')}</td></tr>`;
                return;
            }

            gameEventCache = data.events || [];
            gameEventDefaultsMap = {};
            (data.defaults || []).forEach(d => { gameEventDefaultsMap[d.event_id] = d; });
            setText('gameEventHint', data.apply_hint ? '　' + data.apply_hint : '');
            setText('gameEventMeta', `共 ${gameEventCache.length} 个活动`);
            document.getElementById('gameEventResult').innerHTML = '';

            if (gameEventCache.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" class="muted">游戏库里没有活动记录</td></tr>';
                return;
            }
            tbody.innerHTML = gameEventCache.map(gameEventRow).join('');
            bindRowActions(tbody, 'data-act', {
                toggle: el => toggleGameEvent(parseInt(el.getAttribute('data-id'), 10),
                    el.getAttribute('data-to') === 'on'),
                edit: el => openGameEventEditor(parseInt(el.getAttribute('data-id'), 10)),
            });
        }

        function gameEventRow(e) {
            const on = !!e.enabled;
            const d = gameEventDefaultsMap[e.event_id] || {};
            // 名称用库里的 title —— 那才是客户端真正显示的东西。
            // 库里还是服务端写的英文占位串（pcroomtimepoint 之类）时补一个
            // 推荐中文名，免得操作者对着几个英文串找不着北。
            const name = e.title || d.name || '';
            const locked = d.text_locked
                ? ` <span class="tag tag-warn" title="${escAttr(d.note || '')}">文案重启还原</span>`
                : '';
            const noDetails = e.has_details ? ''
                : ' <span class="tag tag-off" title="game_event_info_details 里没有这一行，文案无法编辑">无文案行</span>';
            const desc = e.description || '';
            const descShown = desc.length > 80 ? desc.slice(0, 80) + '…' : desc;
            return `<tr>
                <td>${esc(e.event_id)}</td>
                <td>${esc(name)}${locked}${noDetails}</td>
                <td>${on ? '<span class="tag tag-on">已开启</span>'
                         : '<span class="tag tag-neutral">已关闭</span>'}</td>
                <td>${esc(e.sort_order)}</td>
                <td class="muted" style="font-size:12px;">${esc(descShown) || '-'}</td>
                <td class="td-actions">
                    <button class="btn btn-sm" data-act="toggle" data-id="${e.event_id}"
                            data-to="${on ? 'off' : 'on'}">${on ? '关闭' : '开启'}</button>
                    <button class="btn btn-sm" data-act="edit" data-id="${e.event_id}">编辑文案</button>
                </td>
            </tr>`;
        }

        async function toggleGameEvent(id, enable) {
            const name = (gameEventCache.find(x => x.event_id === id) || {}).title || '';
            const what = enable ? '开启' : '关闭';
            if (!confirm(`确认${what}活动 ${id}${name ? '（' + name + '）' : ''}？\n\n` +
                '开关对服务端判定即时生效；客户端活动列表要玩家重新登录才刷新。')) return;

            const data = await api('/api/admin/game-event/toggle', 'POST',
                { event_id: id, enabled: enable });
            if (!data) return;
            if (data.ok) {
                showResult('gameEventResult', 'success', data.message || '已保存');
                loadGameEvents();
            } else {
                showResult('gameEventResult', 'error', data.message || '操作失败');
            }
        }

        function openGameEventEditor(id) {
            const e = gameEventCache.find(x => x.event_id === id);
            if (!e) return;
            const d = gameEventDefaultsMap[id] || {};

            gameEventEditingId = id;
            setText('gameEventEditName', `活动 ${id}` + (d.name ? ' · ' + d.name : ''));
            document.getElementById('geTitle').value = e.title || '';
            document.getElementById('geShortName').value = e.short_name || '';
            document.getElementById('geStartNotice').value = e.start_notice || '';
            document.getElementById('geEndNotice').value = e.end_notice || '';
            document.getElementById('geDescription').value = e.description || '';
            document.getElementById('geSortOrder').value = e.sort_order;
            document.getElementById('gameEventEditResult').innerHTML = '';
            setText('gameEventEditFlag', e.updated_at ? '最后改动 ' + fmtUtcGame(e.updated_at) + '（UTC）' : '');

            // 覆盖告警：不写这句，运营就会在"改了→没报错→过几天变回去"里绕圈子。
            document.getElementById('gameEventLockWarn').innerHTML = d.text_locked
                ? `<div class="alert alert-error">注意：${esc(d.note || '该活动的文案由服务端硬编码，重启服务端后会覆盖回原值')}。</div>`
                : '';

            document.getElementById('gameEventEditor').style.display = '';
            document.getElementById('gameEventEditor').scrollIntoView({ block: 'nearest' });
        }

        function closeGameEventEditor() {
            gameEventEditingId = 0;
            document.getElementById('gameEventEditor').style.display = 'none';
        }

        // fillGameEventDefaults 只填表单、**不落库** —— 运营给的《活动中文指令》
        // 里的文案，点完还要再点「保存文案」才写库。
        function fillGameEventDefaults() {
            const d = gameEventDefaultsMap[gameEventEditingId];
            if (!d) {
                showResult('gameEventEditResult', 'error', '该活动没有内置推荐文案');
                return;
            }
            document.getElementById('geTitle').value = d.title || '';
            document.getElementById('geShortName').value = d.short_name || '';
            document.getElementById('geStartNotice').value = d.start_notice || '';
            document.getElementById('geEndNotice').value = d.end_notice || '';
            document.getElementById('geDescription').value = d.description || '';
            showResult('gameEventEditResult', 'success', '已填入推荐文案，确认无误后点「保存文案」');
        }

        async function saveGameEventText() {
            if (!gameEventEditingId) return;
            const sortRaw = document.getElementById('geSortOrder').value.trim();
            const payload = {
                event_id: gameEventEditingId,
                title: document.getElementById('geTitle').value,
                short_name: document.getElementById('geShortName').value,
                start_notice: document.getElementById('geStartNotice').value,
                end_notice: document.getElementById('geEndNotice').value,
                description: document.getElementById('geDescription').value,
                sort_order: sortRaw === '' ? 0 : parseInt(sortRaw, 10),
            };

            const id = gameEventEditingId;
            const data = await api('/api/admin/game-event/update', 'POST', payload);
            if (!data) return;
            if (!data.ok) {
                showResult('gameEventEditResult', 'error', data.message || '保存失败');
                return;
            }

            const msg = (data.message || '已保存') + (data.warning ? '　⚠ ' + data.warning : '');
            // 先刷新列表与编辑器（拿到新的 updated_at），再弹提示 ——
            // 顺序反了的话提示会被编辑器的 innerHTML 清空吃掉。
            await loadGameEvents();
            openGameEventEditor(id);
            showResult('gameEventEditResult', 'success', msg);
        }

        // ==================== 网关管理 ====================

        async function loadGatewayStatus() {
            const data = await api('/api/admin/gateway/status');
            if (!data) return;
            setText('gatewayControlFlag', data.control_enabled ? '（可远程控制）' : '（未开启远程控制）');
            const st = data.status || {};
            document.getElementById('gatewayStatus').innerText =
                `运行状态　${st.active || '-'} / ${st.sub_state || '-'}\n` +
                `进程 PID　${st.pid || '-'}\n` +
                procStatsLines(st) + '\n' +
                `启动命令　${st.exec_start || '-'}\n` +
                `网关日志　${data.gateway_log || '-'}\n` +
                `错误日志　${data.error_log || '-'}`;
        }

        async function gatewayControl(action) {
            const labels = { start: '启动', stop: '停止', restart: '重启' };
            if (!confirm(`确认${labels[action] || action}网关？`)) return;
            const data = await api('/api/admin/gateway/control', 'POST', { action });
            if (data && data.ok === false) alert('操作失败：' + (data.error || '未知错误'));
            loadGatewayStatus();
        }

        // onlyError=true 时强制读错误日志。key 必须是后端识别的 gateway/error，
        // 历史版本把"路径输入框内容"当 key 传，留空就是"无效日志键"，页面永远读不出日志。
        async function loadGatewayLogs(onlyError) {
            const key = onlyError ? 'error' : (document.getElementById('gwLogKey').value || 'gateway');
            const lines = document.getElementById('gwLogLines').value || '300';
            const data = await api(`/api/admin/gateway/logs?key=${encodeURIComponent(key)}&lines=${encodeURIComponent(lines)}`);
            if (!data) return;
            const box = document.getElementById('gatewayLogs');
            const r = data.result || {};
            // 后端 LogResult：{Error string, Lines []string}
            if (r.Error) {
                box.innerText = `读取失败：${r.Error}`;
            } else if (Array.isArray(r.Lines)) {
                box.innerText = r.Lines.length ? r.Lines.join('\n') : '（日志为空）';
            } else {
                box.innerText = JSON.stringify(r, null, 2);
            }
            box.scrollTop = box.scrollHeight;
        }

        // ==================== 游戏端口 ====================

        // 端口状态标签：停用 / 未监听 / 监听中（带在线人数）
        function portStateTag(e) {
            if (!e.enabled) return '<span class="tag tag-off">已停用</span>';
            if (!e.listening) return '<span class="tag tag-off">未监听</span>';
            const n = Number(e.connections) || 0;
            return '<span class="tag tag-on">监听中</span>'
                + (n > 0 ? ` <span class="muted">${n} 人在线</span>` : '');
        }

        // 把保存接口回传的生效结果拼成一句人话
        function portApplyText(data) {
            const apply = data.apply || {};
            const parts = [];
            const opened = apply.opened || [];
            const closed = apply.closed || [];
            if (opened.length) parts.push(`新开端口 ${opened.join('、')}`);
            if (closed.length) {
                const detail = closed.map(c => {
                    const online = Number(c.online_connections) || 0;
                    const why = { disabled: '已停用', removed: '已移除', remapped: '已改绑后端' }[c.reason] || c.reason;
                    return online > 0
                        ? `${c.port}（${why}，仍有 ${online} 个在线连接，未断开）`
                        : `${c.port}（${why}）`;
                });
                parts.push(`关闭端口 ${detail.join('、')}`);
            }
            const failed = apply.failed || {};
            const failedPorts = Object.keys(failed);
            if (failedPorts.length) {
                parts.push(`启动失败 ${failedPorts.map(p => `${p}（${failed[p]}）`).join('、')}`);
            }
            if (!parts.length) parts.push('端口监听无变化');
            return `已保存并立即生效：${parts.join('；')}。`;
        }

        function portRow(entry) {
            const e = entry || { public_port: '', backend_port: '', enabled: true, note: '' };
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td><input type="text" class="pt-public" value="${escAttr(e.public_port)}" style="width:100%;margin:0;"></td>
                <td><input type="text" class="pt-backend" value="${escAttr(e.backend_port)}" style="width:100%;margin:0;"></td>
                <td><input type="checkbox" class="pt-enabled" ${e.enabled ? 'checked' : ''}></td>
                <td class="pt-listening">${portStateTag(e)}</td>
                <td><input type="text" class="pt-note" value="${escAttr(e.note || '')}" style="width:100%;margin:0;"></td>
                <td><button class="btn btn-danger btn-sm" data-act="del">删除</button></td>`;
            tr.querySelector('[data-act="del"]').addEventListener('click', () => tr.remove());
            return tr;
        }

        function addPortRow(entry) {
            document.getElementById('portTable').appendChild(portRow(entry));
        }

        async function loadGamePorts() {
            const data = await api('/api/admin/game-ports');
            if (!data) return;
            if (!data.ok) {
                showResult('portsResult', 'error', data.error || '读取失败');
                return;
            }
            const tbody = document.getElementById('portTable');
            tbody.innerHTML = '';
            const list = data.entries || [];
            list.forEach(e => addPortRow(e));
            const listening = list.filter(e => e.listening).length;
            // 后端未返回 total 字段，这里以 entries 长度为准。
            setText('portsMeta',
                `共 ${list.length} 条，启用 ${data.enabled_count || 0} 条，实际监听 ${listening} 个　配置文件：${data.config_file || '-'}`);
        }

        async function saveGamePorts() {
            const entries = [];
            let bad = '';
            document.querySelectorAll('#portTable tr').forEach(tr => {
                const pub = parseInt(tr.querySelector('.pt-public').value, 10);
                const back = parseInt(tr.querySelector('.pt-backend').value, 10);
                if (!pub && !back) return; // 整行留空视为未填写，跳过
                if (!pub || pub <= 0 || pub > 65535) { bad = `非法公网端口：${tr.querySelector('.pt-public').value}`; return; }
                if (!back || back <= 0 || back > 65535) { bad = `非法后端端口：${tr.querySelector('.pt-backend').value}`; return; }
                entries.push({
                    public_port: pub,
                    backend_port: back,
                    enabled: tr.querySelector('.pt-enabled').checked,
                    note: tr.querySelector('.pt-note').value.trim()
                });
            });
            if (bad) { showResult('portsResult', 'error', bad); return; }
            if (entries.length === 0) { showResult('portsResult', 'error', '至少保留一条端口配置'); return; }
            if (!confirm(`确认保存 ${entries.length} 条端口配置？保存后立即生效（无需重启网关），已在线玩家不会被断开。`)) return;
            const data = await api('/api/admin/game-ports', 'POST', { entries });
            if (!data) return;
            if (data.ok) {
                showResult('portsResult', 'success', portApplyText(data));
                loadGamePorts();
            } else {
                showResult('portsResult', 'error', data.message || data.error || '保存失败');
            }
        }

        // ==================== 外挂监控 ====================

        async function loadAcPlayers() {
            const data = await api('/api/admin/anticheat/players?limit=50&offset=0');
            if (!data) return;
            const tbody = document.getElementById('acPlayerTable');
            tbody.innerHTML = '';
            const list = data.players || [];
            setText('acPlayersMeta', `共 ${data.total || 0} 名玩家有检测记录`);
            if (list.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" class="muted">暂无检测记录</td></tr>';
                return;
            }
            list.forEach(p => {
                tbody.innerHTML += `<tr>
                    <td>${esc(p.account)}</td>
                    <td>${esc(p.detectionCount)}</td>
                    <td>${esc(fmtTime(p.lastDetectionAt))}</td>
                    <td>${esc((p.ruleNames || []).join(', '))}</td>
                    <td>
                        <button class="btn btn-sm" data-act="detail" data-account="${escAttr(p.account)}">明细</button>
                        <button class="btn btn-danger btn-sm" data-act="ban" data-account="${escAttr(p.account)}">封禁</button>
                    </td>
                </tr>`;
            });
            bindRowActions(tbody, 'data-act', {
                detail: (el) => showAcDetails(el.dataset.account),
                ban: (el) => banFromAc(el.dataset.account)
            });
        }

        async function loadAcDetections() {
            const data = await api('/api/admin/anticheat/detections?limit=50&offset=0');
            if (!data) return;
            const tbody = document.getElementById('acDetectionTable');
            tbody.innerHTML = '';
            const list = data.detections || [];
            setText('acDetectionsMeta', `共 ${data.total || 0} 条记录（显示最近 50 条）`);
            if (list.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" class="muted">暂无检测记录</td></tr>';
                return;
            }
            list.forEach(d => {
                tbody.innerHTML += `<tr>
                    <td>${esc(d.ruleName)}</td>
                    <td>${esc(d.description)}</td>
                    <td>${esc(d.actualValue)}</td>
                    <td>${esc(d.thresholdValue)}</td>
                    <td>${esc(d.clientIp)}</td>
                    <td>${esc(fmtTime(d.timestamp))}</td>
                </tr>`;
            });
        }

        async function showAcDetails(account) {
            const data = await api(`/api/admin/anticheat/players/${encodeURIComponent(account)}/details?limit=50&offset=0`);
            if (!data) return;
            const list = data.detections || [];
            if (list.length === 0) { alert(`账号「${account}」暂无明细`); return; }
            const lines = list.map(d =>
                `[${fmtTime(d.timestamp)}] ${d.ruleName}：${d.description}（实际 ${d.actualValue} / 阈值 ${d.thresholdValue}）IP=${d.clientIp}`);
            alert(`账号「${account}」检测明细（共 ${data.total || list.length} 条）：\n\n` + lines.join('\n'));
        }

        async function banFromAc(account) {
            const reason = prompt(`封禁账号「${account}」的原因：`, '外挂检测');
            if (reason === null) return;
            await api('/api/admin/ban', 'POST', { account, reason });
            alert('已封禁');
            loadAcPlayers();
        }

        // ==================== 客户端配置 ====================

        async function loadLauncherConfig() {
            const data = await api('/api/admin/launcher-config');
            if (!data) return;
            document.getElementById('minVersion').value = data.min_version || '';
            document.getElementById('downloadUrl').value = data.download_url || '';
            document.getElementById('updateNotice').value = data.update_notice || '';
            setText('launcherOverride', data.override_file ? `覆盖文件：${data.override_file}` : '');
        }

        async function saveLauncherConfig() {
            const notice = document.getElementById('updateNotice').value;
            await api('/api/admin/launcher-config', 'POST', {
                min_version: document.getElementById('minVersion').value,
                download_url: document.getElementById('downloadUrl').value,
                update_notice: notice
            });
            alert(notice.trim()
                ? '保存成功，登录器「更新内容」已同步'
                : '保存成功（更新公告为空，登录器将显示「暂无更新公告」）');
            loadLauncherConfig();
        }

        // ==================== 维护模式 ====================

        async function loadMaintenance() {
            const data = await api('/api/admin/maintenance');
            if (!data) return;
            document.getElementById('maintenanceEnabled').checked = data.enabled;
            document.getElementById('maintenanceMessage').value = data.message || '';
            document.getElementById('adminAccounts').value = (data.admin_accounts || []).join(', ');
        }

        async function saveMaintenance() {
            const data = await api('/api/admin/maintenance', 'POST', {
                enabled: document.getElementById('maintenanceEnabled').checked,
                message: document.getElementById('maintenanceMessage').value,
                admin_accounts: document.getElementById('adminAccounts').value.split(',').map(s => s.trim()).filter(s => s)
            });
            if (!data) return;
            if (data.ok === false) { alert('保存失败：' + (data.error || '未知错误')); return; }
            // 后端返回 {changed, kicked, ok}：kicked 是启用维护时被踢下线的非白名单账号数。
            let tip = data.changed === false ? '配置无变化' : '保存成功';
            if (data.kicked) tip += `，已踢出 ${data.kicked} 个非白名单在线账号`;
            alert(tip);
            loadMaintenance();
        }

        // ==================== 公告管理 ====================

        // 品级编号与服务端一致：稀有=2、神器=3、史诗=4（5 也按史诗）、传说=6。
        // 5 必须显示成「史诗」，否则服务端按 5 处理的那批装备在后台会显示成空品级。
        function announceRarityText(r) {
            switch (r) {
                case 6: return '传说';
                case 5: return '史诗';
                case 4: return '史诗';
                case 3: return '神器';
                case 2: return '稀有';
                case 1: return '高级';
                default: return '-';
            }
        }

        function announceKindText(k) {
            if (k === 'cleared') return '通关';
            if (k === 'incomplete') return '未通关';
            if (k === 'pickup') return '拾取';
            return k || '-';
        }

        function announcePopupStatusText(s) {
            if (s === 'pending') return '待投递';
            if (s === 'sent') return '已投递';
            if (s === 'expired') return '超时未送达';
            return s || '-';
        }

        function fmtElapsed(ms) {
            if (!ms || ms <= 0) return '-';
            const total = Math.floor(ms / 1000);
            const m = Math.floor(total / 60);
            const s = total % 60;
            return m > 0 ? `${m}分${s}秒` : `${s}秒`;
        }

        function announceDifficultyText(ev) {
            if (ev.hell_mode) return '深渊';
            return '难度' + ev.difficulty;
        }

        // 读配置 + 状态概览。三个请求并发，任一失败不影响其他的展示。
        async function loadAnnounceConfig() {
            const data = await api('/api/admin/announce/config');
            if (!data) return;
            if (data.ok === false) {
                showResult('anConfigMsg', 'error', '读取配置失败：' + (data.error || '未知错误'));
                return;
            }
            const c = data.config || {};

            document.getElementById('anEnabled').checked = !!c.enabled;
            document.getElementById('anReport').checked = !!c.report;
            document.getElementById('anCleared').checked = !!c.cleared;
            document.getElementById('anIncomplete').checked = !!c.incomplete;
            document.getElementById('anPickup').checked = !!c.pickup;
            document.getElementById('anHellEpic').checked = !!c.pickup_hell_epic;
            document.getElementById('anLegend').checked = !!c.pickup_legend;
            document.getElementById('anUnique').checked = !!c.pickup_unique;
            document.getElementById('anStats').checked = !!c.pickup_stats;
            document.getElementById('anItemLink').checked = !!c.pickup_item_link;
            document.getElementById('anDuration').value = c.announce_duration_ms || 5000;
            document.getElementById('anPopupMode').value = c.popup_mode || 0;
            document.getElementById('anRetention').value = c.event_retention_days || 0;
            document.getElementById('anHellName').value = c.hell_difficulty_name || '';
            document.getElementById('anDiffNames').value = (c.difficulty_names || []).join(',');
            document.getElementById('anTplCleared').value = c.template_cleared || '';
            document.getElementById('anTplIncomplete').value = c.template_incomplete || '';
            document.getElementById('anTplPickup').value = c.template_pickup || '';

            setText('anRevision', `配置版本 r${c.revision || 0}，最后更新 ${fmtTime(c.updated_at)}`);
            const tag = document.getElementById('anStateTag');
            if (c.enabled) {
                tag.textContent = '公告服务：运行中';
                tag.className = 'tag tag-on';
            } else {
                tag.textContent = '公告服务：已停用';
                tag.className = 'tag tag-off';
            }
            // 弹窗发送框的 mode 默认跟随配置，但发送时以输入框为准（允许单条覆盖）。
            document.getElementById('anPopupSendMode').value = c.popup_mode || 0;

            loadAnnounceStats();
        }

        async function loadAnnounceStats() {
            const data = await api('/api/admin/announce/stats');
            if (!data || data.ok === false) return;
            setText('anStatsLine',
                `累计：通关 ${data.cleared || 0} · 未通关 ${data.incomplete || 0} · 拾取 ${data.pickup || 0}`);
            setText('anPending', `待投递弹窗 ${data.pending_popups || 0} 条`);
        }

        async function saveAnnounceConfig() {
            const cfg = {
                enabled: document.getElementById('anEnabled').checked,
                report: document.getElementById('anReport').checked,
                cleared: document.getElementById('anCleared').checked,
                incomplete: document.getElementById('anIncomplete').checked,
                pickup: document.getElementById('anPickup').checked,
                pickup_hell_epic: document.getElementById('anHellEpic').checked,
                pickup_legend: document.getElementById('anLegend').checked,
                pickup_unique: document.getElementById('anUnique').checked,
                pickup_stats: document.getElementById('anStats').checked,
                pickup_item_link: document.getElementById('anItemLink').checked,
                announce_duration_ms: parseInt(document.getElementById('anDuration').value, 10) || 5000,
                popup_mode: parseInt(document.getElementById('anPopupMode').value, 10) || 0,
                event_retention_days: parseInt(document.getElementById('anRetention').value, 10) || 0,
                hell_difficulty_name: document.getElementById('anHellName').value.trim(),
                difficulty_names: document.getElementById('anDiffNames').value
                    .split(',').map(s => s.trim()).filter(s => s),
                template_cleared: document.getElementById('anTplCleared').value,
                template_incomplete: document.getElementById('anTplIncomplete').value,
                template_pickup: document.getElementById('anTplPickup').value
            };
            const data = await api('/api/admin/announce/config', 'POST', { config: cfg });
            if (!data) return;
            if (data.ok === false) {
                showResult('anConfigMsg', 'error', '保存失败：' + (data.error || '未知错误'));
                return;
            }
            showResult('anConfigMsg', 'success', data.message || '已保存并热重载');
            loadAnnounceConfig();
        }

        async function sendAnnouncePopup() {
            const message = document.getElementById('anPopupText').value.trim();
            if (!message) { alert('请先填写弹窗内容'); return; }
            const mode = parseInt(document.getElementById('anPopupSendMode').value, 10) || 0;
            if (!confirm(`确认向全部在线玩家推送弹窗公告？\n\n${message}`)) return;

            const data = await api('/api/admin/announce/popup', 'POST', { message: message, mode: mode });
            if (!data) return;
            if (data.ok === false) {
                showResult('anPopupMsg', 'error', '发送失败：' + (data.error || data.message || '未知错误'));
                return;
            }
            showResult('anPopupMsg', 'success', data.message || `已入队（#${data.id}）`);
            document.getElementById('anPopupText').value = '';
            loadAnnouncePopups(1);
            loadAnnounceStats();
        }

        let anPopupPage = 1;

        async function loadAnnouncePopups(page) {
            if (page < 1) page = 1;
            anPopupPage = page;
            const status = document.getElementById('anPopupFilter').value;
            const qs = new URLSearchParams({ page: String(page), page_size: '20' });
            if (status) qs.set('status', status);

            const data = await api('/api/admin/announce/popups?' + qs.toString());
            if (!data) return;
            const tbody = document.getElementById('anPopupTable');
            tbody.innerHTML = '';
            if (data.ok === false) {
                tbody.innerHTML = `<tr><td colspan="7">${esc(data.error || '查询失败')}</td></tr>`;
                return;
            }

            (data.popups || []).forEach(p => {
                const tr = document.createElement('tr');
                // 任何状态都能删（软删除，库里留痕），所以不再有 disabled 的情况。
                // 旧实现只让删「待投递」，而后台最常想删的就是刚发出去那几条 ——
                // 按钮点上去没反应，就是本次报障的"撤销操作无效"。
                tr.innerHTML =
                    `<td>${p.id}</td>` +
                    `<td>${esc(p.message)}</td>` +
                    `<td>${esc(announcePopupStatusText(p.status))}</td>` +
                    `<td class="muted">${esc(p.created_by || '-')}</td>` +
                    `<td>${fmtTime(p.created_at)}</td>` +
                    `<td>${p.sent_at ? fmtTime(p.sent_at) : '-'}</td>` +
                    `<td><button class="btn btn-sm btn-danger" data-popup-del="${p.id}">删除</button></td>`;
                tbody.appendChild(tr);
            });
            if (!tbody.children.length) {
                tbody.innerHTML = '<tr><td colspan="7" class="muted">没有记录</td></tr>';
            }
            // 撤销按钮：用 addEventListener 而不是内联 onclick，
            // 因为 id 虽是数字，但保持与其它表格一致的做法（避免以后有人把可控字段塞进来）。
            tbody.querySelectorAll('[data-popup-del]').forEach(btn => {
                btn.addEventListener('click', () => deleteAnnouncePopup(btn.getAttribute('data-popup-del')));
            });

            const total = data.total || 0;
            const pageSize = data.page_size || 20;
            const pages = Math.max(1, Math.ceil(total / pageSize));
            setText('anPopupPageInfo', `共 ${total} 条，第 ${page} / ${pages} 页`);
        }

        async function deleteAnnouncePopup(id) {
            if (!confirm(`从后台列表删除公告 #${id}？\n\n已经发出去的公告收不回来，删除只是让它不再显示在这个列表里（库里仍保留记录）。`)) return;
            const data = await api('/api/admin/announce/popup?id=' + encodeURIComponent(id), 'DELETE');
            if (!data) return;
            if (data.ok === false) { alert('删除失败：' + (data.error || data.message || '未知错误')); return; }
            loadAnnouncePopups(anPopupPage);
            loadAnnounceStats();
        }

        let anEventPage = 1;

        async function loadAnnounceEvents(page) {
            if (page < 1) page = 1;
            anEventPage = page;
            const qs = new URLSearchParams({ page: String(page), page_size: '50' });
            const kind = document.getElementById('anEventKind').value;
            const keyword = document.getElementById('anEventKeyword').value.trim();
            const account = document.getElementById('anEventAccount').value.trim();
            const minRarity = document.getElementById('anEventMinRarity').value;
            if (kind) qs.set('kind', kind);
            if (keyword) qs.set('keyword', keyword);
            if (account) qs.set('account', account);
            if (minRarity && minRarity !== '0') qs.set('min_rarity', minRarity);
            if (document.getElementById('anEventBroadcastOnly').checked) qs.set('broadcast_only', '1');

            const data = await api('/api/admin/announce/events?' + qs.toString());
            if (!data) return;
            const tbody = document.getElementById('anEventTable');
            tbody.innerHTML = '';
            if (data.ok === false) {
                tbody.innerHTML = `<tr><td colspan="9">${esc(data.error || '查询失败')}</td></tr>`;
                return;
            }

            (data.events || []).forEach(ev => {
                const isPickup = ev.kind === 'pickup';
                const stats = [];
                if (ev.item_level > 0) stats.push('Lv.' + ev.item_level);
                if (ev.physical_attack > 0) stats.push('物攻+' + ev.physical_attack);
                if (ev.magical_attack > 0) stats.push('魔攻+' + ev.magical_attack);
                if (ev.physical_defense > 0) stats.push('物防+' + ev.physical_defense);
                if (ev.magical_defense > 0) stats.push('魔防+' + ev.magical_defense);

                const tr = document.createElement('tr');
                tr.innerHTML =
                    `<td>${fmtTime(ev.created_at)}</td>` +
                    `<td>${esc(announceKindText(ev.kind))}</td>` +
                    `<td>${esc(ev.character_name || '-')}</td>` +
                    `<td class="muted">${esc(ev.account || '-')}</td>` +
                    `<td>${esc(ev.dungeon_name || '-')}<span class="muted"> / ${esc(announceDifficultyText(ev))}</span></td>` +
                    `<td>${isPickup ? esc(ev.item_name || '-') : '-'}` +
                    (isPickup && ev.broadcast ? ' <span class="tag tag-on">已播报</span>' : '') + '</td>' +
                    `<td>${isPickup ? esc(announceRarityText(ev.item_rarity)) : '-'}</td>` +
                    `<td class="muted">${esc(stats.join(' ') || '-')}</td>` +
                    `<td>${fmtElapsed(ev.elapsed_ms)}</td>`;
                tbody.appendChild(tr);
            });
            if (!tbody.children.length) {
                tbody.innerHTML = '<tr><td colspan="9" class="muted">没有记录</td></tr>';
            }

            const total = data.total || 0;
            const pageSize = data.page_size || 50;
            const pages = Math.max(1, Math.ceil(total / pageSize));
            setText('anEventPageInfo', `共 ${total} 条，第 ${page} / ${pages} 页`);
        }

        document.getElementById('anPopupFilter').addEventListener('change', () => loadAnnouncePopups(1));
        document.getElementById('anEventKind').addEventListener('change', () => loadAnnounceEvents(1));

        // ==================== 初始化 ====================

        document.getElementById('authKey').value = authKey;
        document.getElementById('authKey').addEventListener('change', (e) => {
            authKey = e.target.value;
            localStorage.setItem('authKey', authKey);
        });

        loadOnline();
    