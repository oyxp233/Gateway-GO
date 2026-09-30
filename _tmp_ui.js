
        let authKey = localStorage.getItem('authKey') || '';

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
            server: () => { loadServerStatus(); loadBackups(); loadPluginConfig(); loadRegisterBonus(); },
            gateway: loadGatewayStatus,
            ports: loadGamePorts,
            anticheat: () => { loadAcPlayers(); loadAcDetections(); },
            launcher: loadLauncherConfig,
            maintenance: loadMaintenance
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

        async function loadAccounts(page) {
            accountPage = Math.max(1, page || 1);
            const keyword = document.getElementById('accountKeyword').value;
            const data = await api(`/api/admin/accounts?keyword=${encodeURIComponent(keyword)}&page=${accountPage}&page_size=50`);
            if (!data) return;
            const tbody = document.getElementById('accountTable');
            tbody.innerHTML = '';
            (data.accounts || []).forEach(a => {
                tbody.innerHTML += `<tr>
                    <td>${esc(a.name)}</td>
                    <td>${esc(a.m_id)}</td>
                    <td>${esc(a.cera)}</td>
                    <td>${esc(fmtTime(a.last_login_at))}</td>
                    <td>${esc(a.last_login_ip)}</td>
                    <td>
                        <button class="btn btn-sm" data-act="pwd" data-account="${escAttr(a.name)}">重置密码</button>
                        <button class="btn btn-sm" data-act="device" data-account="${escAttr(a.name)}">解绑设备</button>
                        <button class="btn btn-sm" data-act="unlock" data-account="${escAttr(a.name)}">解锁</button>
                        <button class="btn btn-sm" data-act="roles" data-account="${escAttr(a.name)}">查角色</button>
                        <button class="btn btn-sm" data-act="items" data-account="${escAttr(a.name)}">发道具</button>
                        <button class="btn btn-sm btn-danger" data-act="del" data-account="${escAttr(a.name)}">删除</button>
                    </td>
                </tr>`;
            });
            bindRowActions(tbody, 'data-act', {
                pwd: (el) => resetPassword(el.dataset.account),
                device: (el) => resetDevice(el.dataset.account),
                unlock: (el) => unlockAccount(el.dataset.account),
                roles: (el) => showRoles(el.dataset.account),
                items: (el) => sendItems(el.dataset.account),
                del: (el) => deleteAccount(el.dataset.account)
            });

            const total = data.total || 0;
            const pageSize = data.page_size || 50;
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
            const md5 = prompt(`重置「${account}」的密码。\n请输入新密码的 32 位小写 MD5：`);
            if (!md5) return;
            if (md5.length !== 32) { alert('MD5 必须是 32 位'); return; }
            const data = await api('/api/admin/reset-password', 'POST', { account, newPasswordMd5: md5 });
            if (data) alert(data.message || (data.ok ? '重置成功' : '重置失败'));
        }

        async function resetDevice(account) {
            if (!confirm(`解除「${account}」的设备绑定？该账号在线会话会被断开。`)) return;
            const data = await api('/api/admin/reset-device', 'POST', { account });
            if (data) alert(data.message || (data.ok ? '解绑成功' : '解绑失败'));
        }

        async function unlockAccount(account) {
            const data = await api('/api/admin/unlock', 'POST', { account });
            if (data) alert(`账号 ${account} 解锁完成${data.was_locked ? '' : '（该账号原本未被锁定）'}`);
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

        // 解析批量输入框：按行/逗号/空格分隔，去重去空。
        function parseBatchAccounts() {
            const raw = document.getElementById('batchDelInput').value || '';
            const seen = new Set();
            const out = [];
            raw.split(/[\s,，;；]+/).forEach(s => {
                const name = s.trim();
                if (name && !seen.has(name)) { seen.add(name); out.push(name); }
            });
            return out;
        }

        // 批量删除：dryRun 预演时逐条列出结果，确认后才真删。
        async function batchDeleteAccounts(dryRun) {
            const accounts = parseBatchAccounts();
            if (accounts.length === 0) { alert('请先填写要删除的账号名'); return; }
            if (accounts.length > 200) { alert(`单次最多 200 个账号，当前 ${accounts.length} 个`); return; }

            const purgeLogs = document.getElementById('batchDelPurge').checked;

            if (dryRun) {
                const data = await api('/api/admin/delete-accounts', 'POST', { accounts, purgeLogs, dryRun: true });
                if (!data) return;
                renderBatchDeleteResult(data);
                return;
            }

            if (!confirm(`确认永久删除 ${accounts.length} 个账号？\n\n${accounts.join('\n')}\n\n` +
                `删除会同时清理网关库账号行与设备历史${purgeLogs ? '，并清理审计流水' : '（审计流水保留）'}。\n` +
                '名下仍有角色的账号会被跳过。此操作不可撤销。')) return;

            const data = await api('/api/admin/delete-accounts', 'POST', { accounts, purgeLogs });
            if (!data) return;
            renderBatchDeleteResult(data);
            loadAccounts(accountPage);
        }

        function renderBatchDeleteResult(data) {
            const box = document.getElementById('batchDelResult');
            if (!box) return;
            const rows = (data.results || []).map(r => `<tr>
                <td>${esc(r.account)}</td>
                <td>${r.ok ? '✅ 将删除' : (r.code === 'has_characters' ? '⏭ 跳过（有角色）'
                    : r.code === 'not_found' ? '⏭ 跳过（不存在）' : '❌ 失败')}</td>
                <td>${esc(r.message || '')}</td>
            </tr>`).join('');
            const summary = data.dry_run
                ? `预演完成（未执行任何修改）：可删 ${data.deleted} 个，跳过 ${data.skipped} 个，异常 ${data.failed} 个`
                : `删除完成：成功 ${data.deleted} 个，跳过 ${data.skipped} 个，失败 ${data.failed} 个`;
            box.innerHTML = `<div class="alert alert-${data.failed > 0 ? 'error' : 'success'}">${esc(summary)}</div>
                <table><thead><tr><th style="width:28%">账号</th><th style="width:18%">结果</th><th>说明</th></tr></thead>
                <tbody>${rows}</tbody></table>`;
        }

        async function showRoles(account) {
            const data = await api(`/api/admin/roles?account=${encodeURIComponent(account)}`);
            if (!data) return;
            const roles = data.roles || [];
            if (roles.length === 0) {
                alert(`账号「${account}」没有查到角色（或游戏库未配置）`);
                return;
            }
            // 后端 database.RoleInfo 未加 json tag，字段名为 Go 导出名。
            const lines = roles.map(r => {
                if (typeof r === 'string') return r;
                const id = r.CharacterId !== undefined ? r.CharacterId : r.character_id;
                const name = r.Name !== undefined ? r.Name : r.name;
                const level = r.Level !== undefined ? r.Level : r.level;
                const job = r.Job !== undefined ? r.Job : r.job;
                const exp = r.Exp !== undefined ? r.Exp : r.exp;
                return `角色ID=${id}　名称=${name}　等级=${level}　职业=${job}　经验=${exp}`;
            });
            alert(`账号「${account}」的角色（共 ${roles.length} 个）：\n\n` + lines.join('\n'));
        }

        async function sendItems(account) {
            const charId = prompt(`向账号「${account}」的角色投递道具。\n请输入角色 ID：`);
            if (!charId) return;
            const tpl = prompt('请输入物品 ID：');
            if (!tpl) return;
            const count = prompt('请输入数量：', '1');
            if (!count) return;
            const data = await api('/api/admin/send-items', 'POST', {
                characterId: parseInt(charId, 10),
                items: [{ item_template_id: parseInt(tpl, 10), count: parseInt(count, 10) }]
            });
            if (data) alert(data.message || (data.ok ? '已投递' : '投递失败'));
        }

        async function resetAllPasswords(dryRun) {
            const md5 = document.getElementById('allPwdMd5').value.trim();
            if (md5.length !== 32) { alert('MD5 必须是 32 位'); return; }
            if (!dryRun && !confirm('确认对所有账号执行密码重置？此操作不可撤销。')) return;
            const data = await api('/api/admin/reset-all-passwords', 'POST', { newPasswordMd5: md5, dryRun });
            if (!data) return;
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

        // ==================== 全服发放 ====================

        function bcItemRow(tpl, count, kind, itemType) {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td><input type="text" class="bc-tpl" value="${escAttr(tpl || '')}" style="width:100%;margin:0;"></td>
                <td><input type="text" class="bc-count" value="${escAttr(count === undefined ? 1 : count)}" style="width:100%;margin:0;"></td>
                <td><input type="text" class="bc-kind" value="${escAttr(kind === undefined ? '' : kind)}" placeholder="默认3" style="width:100%;margin:0;"></td>
                <td><input type="text" class="bc-itemtype" value="${escAttr(itemType === undefined ? '' : itemType)}" placeholder="默认0" style="width:100%;margin:0;"></td>
                <td><button class="btn btn-danger btn-sm" data-act="delfile">删除</button></td>`;
            tr.querySelector('[data-act="delfile"]').addEventListener('click', () => tr.remove());
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

        async function loadServerStatus() {
            const data = await api('/api/admin/server/status');
            if (!data) return;
            setText('serverControlFlag', data.control_enabled ? '（可远程控制）' : '（未开启远程控制）');
            const st = data.status || {};
            document.getElementById('serverStatus').innerText =
                `运行状态　${st.active || '-'} / ${st.sub_state || '-'}\n` +
                `进程 PID　${st.pid || '-'}\n` +
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
            showResult('serverPvfResult', 'success', '正在备份，请稍候…');
            const data = await api('/api/admin/server/backup', 'POST', {});
            if (!data) return;
            showResult('serverPvfResult', data.ok ? 'success' : 'error',
                data.ok ? '备份完成' : (data.error || '备份失败'));
            loadBackups();
        }

        async function loadBackups() {
            const data = await api('/api/admin/server/backups');
            if (!data) return;
            setText('backupDir', data.directory || '');
            const tbody = document.getElementById('backupTable');
            tbody.innerHTML = '';
            const items = data.items || [];
            if (items.length === 0) {
                tbody.innerHTML = '<tr><td colspan="3" class="muted">暂无备份</td></tr>';
                return;
            }
            // 后端 ListBackups 返回 []string（完整路径）；无备份时 JSON 里是 null。
            // 兼容将来若改为对象数组的情况。
            items.forEach(it => {
                const full = typeof it === 'string'
                    ? it
                    : (it && (it.path || it.name || it.file) || '');
                const name = full.split(/[\\/]/).pop() || full || '-';
                const size = (it && typeof it === 'object' && it.size !== undefined) ? fmtSize(it.size) : '-';
                let time = '-';
                if (it && typeof it === 'object') {
                    const t = it.modified_at || it.modified || it.created_at;
                    time = typeof t === 'number' ? fmtTime(t) : (t || '-');
                }
                tbody.innerHTML += `<tr><td title="${escAttr(full)}">${esc(name)}</td><td>${esc(size)}</td><td>${esc(time)}</td></tr>`;
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

        async function loadPluginConfig() {
            const data = await api('/api/admin/plugin-config');
            if (!data) return;
            setText('pluginPath', data.path ? (data.exists ? data.path : data.path + '（文件不存在）') : '（未配置 ini 路径）');
            const tbody = document.getElementById('pluginTable');
            tbody.innerHTML = '';
            const entries = data.entries || [];
            if (entries.length === 0) {
                tbody.innerHTML = '<tr><td colspan="3" class="muted">暂无可配置项</td></tr>';
                return;
            }
            entries.forEach(e => {
                const attrs = `data-section="${escAttr(e.section)}" data-key="${escAttr(e.key)}" data-kind="${escAttr(e.kind)}"`;
                let inputHtml;
                if (e.kind === 'toggle') {
                    const on = String(e.value).toLowerCase() === 'true' || String(e.value) === '1' || String(e.value).toLowerCase() === 'yes';
                    inputHtml = `<input type="checkbox" class="pl-value" ${attrs} ${on ? 'checked' : ''}>`;
                } else {
                    inputHtml = `<input type="text" class="pl-value" ${attrs} value="${escAttr(e.value)}" style="width:100%;margin:0;">`;
                }
                tbody.innerHTML += `<tr>
                    <td>${esc(e.section)}</td>
                    <td>${esc(e.key)}</td>
                    <td>${inputHtml}</td>
                </tr>`;
            });
        }

        async function savePluginConfig() {
            const toggles = [];
            document.querySelectorAll('.pl-value').forEach(el => {
                const kind = el.dataset.kind;
                toggles.push({
                    section: el.dataset.section,
                    key: el.dataset.key,
                    kind: kind,
                    value: kind === 'toggle' ? (el.checked ? 'true' : 'false') : el.value
                });
            });
            if (toggles.length === 0) { showResult('pluginResult', 'error', '没有可保存的配置项'); return; }
            const data = await api('/api/admin/plugin-config', 'POST', { toggles });
            if (!data) return;
            showResult('pluginResult', data.ok ? 'success' : 'error',
                data.ok ? '已保存，重启服务端后生效' : (data.message || data.error || '保存失败'));
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

        // ==================== 网关管理 ====================

        async function loadGatewayStatus() {
            const data = await api('/api/admin/gateway/status');
            if (!data) return;
            setText('gatewayControlFlag', data.control_enabled ? '（可远程控制）' : '（未开启远程控制）');
            const st = data.status || {};
            document.getElementById('gatewayStatus').innerText =
                `运行状态　${st.active || '-'} / ${st.sub_state || '-'}\n` +
                `进程 PID　${st.pid || '-'}\n` +
                `启动命令　${st.exec_start || '-'}\n` +
                `网关日志　${data.gateway_log || '-'}\n` +
                `错误日志　${data.error_log || '-'}`;
            const gw = document.getElementById('gwLogPath');
            gw.placeholder = '日志路径（留空=使用网关默认日志）';
        }

        async function gatewayControl(action) {
            const labels = { start: '启动', stop: '停止', restart: '重启' };
            if (!confirm(`确认${labels[action] || action}网关？`)) return;
            const data = await api('/api/admin/gateway/control', 'POST', { action });
            if (data && data.ok === false) alert('操作失败：' + (data.error || '未知错误'));
            loadGatewayStatus();
        }

        // onlyError=true 时改用错误日志路径作为 key。
        async function loadGatewayLogs(onlyError) {
            const gws = await api('/api/admin/gateway/status');
            if (!gws) return;
            const key = onlyError ? (gws.error_log || '') : document.getElementById('gwLogPath').value.trim();
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
            setText('launcherOverride', data.override_file ? `覆盖文件：${data.override_file}` : '');
        }

        async function saveLauncherConfig() {
            await api('/api/admin/launcher-config', 'POST', {
                min_version: document.getElementById('minVersion').value,
                download_url: document.getElementById('downloadUrl').value
            });
            alert('保存成功');
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

        // ==================== 初始化 ====================

        document.getElementById('authKey').value = authKey;
        document.getElementById('authKey').addEventListener('change', (e) => {
            authKey = e.target.value;
            localStorage.setItem('authKey', authKey);
        });

        loadOnline();
    