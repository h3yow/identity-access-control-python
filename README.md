# identity-access-control-python

本仓库在 FastAPI 后端之上实现了一套**服务自身的身份认证与会话访问控制能力**：
令牌签发 / 刷新 / 撤销 / 授权判定全部在本地完成，仅依赖 Python 标准库
（HMAC-SHA256 签名），不依赖外部身份服务或真实凭据。

## 架构

| 模块 | 职责 |
| --- | --- |
| `app/errors.py` | 可区分的失败原因 `DenyReason` 与 `AuthError` |
| `app/tokens.py` | 类 JWT 令牌编解码（HMAC-SHA256）、`KeyRing` 签名密钥轮换 |
| `app/sessions.py` | 会话与刷新令牌族存储：一次性轮换、重放检测、撤销、按主体容量限制 |
| `app/audit.py` | 有界、线程安全的会话安全审计日志（动作 / 结果 / 过滤 / 分页） |
| `app/authz.py` | RBAC：角色 → `资源:操作` 权限点，授权判定 |
| `app/service.py` | `AuthService` 门面：登录、刷新、登出、会话管理、审计、密钥轮换、授权 |
| `app/api.py` | FastAPI HTTP 入口，错误到状态码的映射 |

## 令牌生命周期

- 令牌格式：`base64url(header).base64url(payload).base64url(hmac_sha256)`，
  header 携带 `kid` 标识签名密钥。
- **签发**：`POST /login` 返回访问令牌（默认 300s）与刷新令牌（默认 3600s），
  同时创建会话（一个会话对应一个刷新令牌族）。请求体可选 `device_label`
  （设备/客户端说明），不传时为空字符串，登录行为完全一致。
- **刷新**：`POST /refresh` 提交刷新令牌，服务端**一次性轮换**——
  旧刷新令牌立即作废，签发新一代令牌对，并更新会话的"最近刷新时间"。
- **登出**：`POST /logout`（Bearer 访问令牌）使当前会话失效。
- **撤销**：会话自助管理（见下），使指定会话的访问令牌与刷新链路立即失效。

## 会话自助管理

会话是可管理的一等对象，全部状态仅保存在本地内存：

- `GET /sessions`（任意已登录用户）：查看**自己**当前仍有效的会话，
  每条含 `session_id`、`created_at`（创建时间）、`last_refreshed_at`
  （最近一次刷新时间）、`status`（`active`/`logged_out`/`revoked`/`reused`）、
  `device_label`（设备说明）。
- `POST /sessions/{session_id}/revoke`：撤销**自己的**某个会话；
  撤销后仅该会话的访问令牌与整条刷新链路立即失效，其他会话不受影响。
  会话不存在返回 `session_not_found`，会话属于他人返回 `forbidden`。
  **不允许撤销当前会话**（由本次请求的 Bearer 令牌确定）：此类请求在
  触碰任何状态之前被拒绝，返回 HTTP `409` + `current_session_revoke_denied`，
  并写入一条 `denied:current_session_revoke_denied` 审计记录。被拒绝的请求
  不留任何副作用——当前访问令牌、整条刷新链路、名下其他会话均保持可用，
  会话列表如实反映真实状态。如需退出当前会话请使用 `POST /logout`。
- `POST /sessions/revoke-others`：撤销除**当前会话**外的其他有效会话。
  当前会话由 Bearer 令牌确定，固定保留，因此不可能被误撤销。

### 并发会话容量限制

- 同一主体同时有效的会话数有**硬上限，默认 5**；仅统计 `active` 会话，
  已登出 / 撤销 / 重放终止的会话不占名额（登出或撤销后可再登录）。
- 通过本地配置调整：构造 `AuthService(max_sessions_per_subject=N)`；
  容量按主体独立计数，互不影响。
- 达到上限后的新登录会得到**明确、稳定、可区分**的拒绝：
  HTTP `409` + `session_limit_reached`。**不会**静默挤掉旧会话，
  容量检查与会话插入在同一把锁内原子完成，先于任何令牌签发，
  因此不会留下半成功状态，也不会留下还能使用的令牌。
- 多个登录并发到达时，最终有效会话数绝不超过上限，成功数与最终状态一致。

## 会话安全审计

以下动作都会写入审计日志：登录（**含因容量限制被拒绝的登录**）、
刷新成功或被拒绝（含格式错误、过期、重放）、主动登出、单会话撤销、
批量撤销其他会话、会话因刷新令牌重放而异常终止、密钥轮换、角色权限调整。

每条记录包含：单调递增序号 `seq`、`timestamp`（epoch 秒）、`subject`（主体）、
`session_id`（适用时）、`action`（动作）、`result`（`success` 或
`denied:<原因>`）以及 `detail`。

- 查询入口 `GET /audit`，支持参数：`subject`、`action`（可重复，过滤动作）、
  `start`/`end`（epoch 秒闭区间）、`offset`、`limit`；
  返回 `items` / `total` / `offset` / `limit`，**固定按序号升序稳定排序**。
- **权限范围**：普通用户不带条件时只能看到自己的记录；显式查询他人
  （`subject` 非本人）返回 `403 forbidden`。具备 `audit:read` 权限点的角色
  可以按用户、动作、时间范围查询全部记录并分页。
- **并发写入**：追加与容量裁剪在单把锁内完成，并发写入不丢记录、不重复，
  序号全局连续递增（即使旧记录被淘汰也不复用）。
- **保留与清理**：审计日志有明确容量上限，默认最多保留 **10 000 条**，
  通过 `AuthService(audit_max_records=N)` 本地配置调整。写满后新记录照常写入，
  同时按 FIFO **淘汰最旧记录**（环形有界 deque），内存占用恒定、行为可预期，
  不会无限增长。

### 刷新令牌轮换与重放

- 轮换在单把锁内完成"校验旧令牌 → 标记已用 → 登记新令牌"，
  因此**同一刷新令牌的并发刷新只有一个成功**，其余得到明确的
  `refresh_token_reused` 拒绝。
- 已使用的刷新令牌再次被提交视为**重放**：整个会话族被撤销
  （族内新签发的访问/刷新令牌一并失效），拒绝原因为 `refresh_token_reused`，
  与格式错误（`token_malformed`）、过期（`token_expired`）可区分。
- 并发双提交与重放攻击在服务端不可区分，统一按重放处理，
  保证任何时刻不存在两份同时生效的有效凭据。

### 撤销与密钥轮换

- 访问令牌校验时**实时查询会话状态**（无缓存），登出 / 撤销 / 重放撤销
  立即生效，所有受保护入口判定一致，不存在短暂放行窗口。
- `POST /keys/rotate`（需 `keys:rotate` 权限）轮换签名密钥：
  旧密钥进入**退役集合**（仍可验签但令牌一律按 `token_revoked` 拒绝），
  因此轮换前签发的令牌在其原始有效期内也立即失效；
  以密钥标识而非时间阈值判定，避免时钟秒级粒度的边界歧义。

## 授权模型

- 权限点细化到具体操作：`资源:操作`（如 `document:read`、`session:revoke`）。
- 角色是权限点的集合，用户登录时被分配角色；角色权限通过
  `PUT /roles/{role}/permissions`（需 `role:manage` 权限）调整，
  **下一次请求即生效**（判定路径无任何缓存快照）。
- 判定顺序：先认证（令牌有效性、会话状态），再鉴权（权限点），
  最后才检查资源存在性——**越权请求一律返回 `forbidden`，
  不泄漏目标资源是否存在**；授权通过但资源不存在才返回 `resource_not_found`。

### 失败原因一览

| 原因 | HTTP | 含义 |
| --- | --- | --- |
| `token_malformed` | 401 | 格式错误 / 签名无效 / 令牌类型用错 |
| `token_expired` | 401 | 已过期 |
| `token_revoked` | 401 | 登出 / 主动撤销 / 密钥轮换后失效 |
| `refresh_token_reused` | 401 | 刷新令牌重放，会话族已撤销 |
| `session_not_found` | 401 | 会话不存在 |
| `session_limit_reached` | 409 | 并发会话数达到上限，明确拒绝（不挤掉旧会话） |
| `current_session_revoke_denied` | 409 | 不允许撤销当前会话（无任何副作用，请改用登出） |
| `forbidden` | 403 | 已认证但缺少权限（含跨用户操作，不泄漏资源存在性） |
| `resource_not_found` | 404 | 授权通过但资源不存在 |

### 权限点一览（新增）

| 权限点 | 作用 |
| --- | --- |
| `audit:read` | 查询全部主体的审计记录并按条件过滤分页（无此权限只能查自己） |
| `keys:rotate` | 轮换签名密钥 |
| `role:manage` | 调整角色权限 |
| `document:read` 等 | 业务资源权限点 |

会话自助管理（查看自己的会话、撤销自己的会话、撤销自己的其他会话）
只要求已登录，不依赖额外角色权限；归属不匹配一律 `forbidden`。

### 兼容行为

- 登录请求中 `device_label`、`roles` 均可选；旧客户端请求体不变即可继续工作。
- 会话撤销端点路径 `POST /sessions/{session_id}/revoke` 保持不变，
  语义从"需 `session:revoke` 权限的管理端撤销"收敛为"已登录用户自助撤销自己
  的会话"（归属校验）；跨用户返回 `forbidden`。
- 刷新轮换、重放检测、密钥轮换、权限即时生效等既有语义与失败原因保持不变。

## 本地验证

```bash
# 安装依赖
uv sync

# 运行测试（日志会打印每个用例的输入与判定依据）
uv run python -m pytest tests/ -q

# 启动服务
uv run uvicorn main:app --reload
```

手动验证示例：

```bash
# 登录（设备说明可选；同一用户默认最多 5 个并发有效会话，超出返回 409）
curl -s -X POST localhost:8000/login -H 'content-type: application/json' \
  -d '{"subject":"alice","roles":["reader"],"device_label":"my-laptop"}'

# 查看自己当前有效的会话
curl -s localhost:8000/sessions -H "Authorization: Bearer <access_token>"

# 撤销自己的某个会话 / 撤销除当前会话外的其他会话
curl -s -X POST localhost:8000/sessions/<session_id>/revoke \
  -H "Authorization: Bearer <access_token>"
curl -s -X POST localhost:8000/sessions/revoke-others \
  -H "Authorization: Bearer <access_token>"

# 撤销当前会话会被明确拒绝（409 current_session_revoke_denied），
# 且当前令牌、刷新链路与其他会话均不受影响；退出当前会话请用 /logout
curl -s -X POST localhost:8000/sessions/<当前会话的session_id>/revoke \
  -H "Authorization: Bearer <当前会话的access_token>"

# 查询审计（普通用户只能查自己；具备 audit:read 可带 subject 查全部）
curl -s "localhost:8000/audit?action=login&limit=20&offset=0" \
  -H "Authorization: Bearer <access_token>"

# 访问受保护资源
curl -s localhost:8000/resources/doc-1 -H "Authorization: Bearer <access_token>"

# 刷新（再次提交同一刷新令牌将触发重放检测）
curl -s -X POST localhost:8000/refresh -H 'content-type: application/json' \
  -d '{"refresh_token":"<refresh_token>"}'
```

测试覆盖：并发刷新（32 线程仅 1 成功）、刷新令牌重放并撤销会话族、
登出 / 撤销 / 密钥轮换后继续使用、权限调整立即生效、越权不泄漏资源存在性、
各类失败原因可区分；以及新增的**并发登录触及容量上限（40 线程最终不超过 5）**、
设备说明与会话列表字段、单会话撤销的隔离性、批量撤销只影响其他会话且保留当前、
**撤销当前会话被 409 拒绝且拒绝后访问令牌 / 刷新链路 / 其他会话全部不受影响**、
审计并发写入（16×200 条不丢不重、序号连续）、审计容量 FIFO 淘汰、
分页与按主体/动作/时间过滤稳定排序、普通用户跨用户撤销或查询审计被拒绝。
