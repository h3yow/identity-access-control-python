# identity-access-control-python

本仓库在 FastAPI 后端之上实现了一套**服务自身的身份认证与会话访问控制能力**：
令牌签发 / 刷新 / 撤销 / 授权判定全部在本地完成，仅依赖 Python 标准库
（HMAC-SHA256 签名），不依赖外部身份服务或真实凭据。

## 架构

| 模块 | 职责 |
| --- | --- |
| `app/errors.py` | 可区分的失败原因 `DenyReason` 与 `AuthError` |
| `app/tokens.py` | 类 JWT 令牌编解码（HMAC-SHA256）、`KeyRing` 签名密钥轮换 |
| `app/sessions.py` | 会话与刷新令牌族存储：一次性轮换、重放检测、撤销、并发容量限制 |
| `app/audit.py` | 安全审计日志：动作记录、有界容量、过滤 / 稳定排序 / 分页查询 |
| `app/authz.py` | RBAC：角色 → `资源:操作` 权限点，授权判定 |
| `app/service.py` | `AuthService` 门面：登录、刷新、登出、会话自助管理、审计、密钥轮换、授权 |
| `app/api.py` | FastAPI HTTP 入口，错误到状态码的映射 |

## 令牌生命周期

- 令牌格式：`base64url(header).base64url(payload).base64url(hmac_sha256)`，
  header 携带 `kid` 标识签名密钥。
- **签发**：`POST /login` 返回访问令牌（默认 300s）与刷新令牌（默认 3600s），
  同时创建会话（一个会话对应一个刷新令牌族）。
- **刷新**：`POST /refresh` 提交刷新令牌，服务端**一次性轮换**——
  旧刷新令牌立即作废，签发新一代令牌对。
- **登出**：`POST /logout`（Bearer 访问令牌）使会话失效。
- **撤销**：`POST /sessions/{id}/revoke` 撤销自己的某个会话（详见下文会话管理）。

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

## 会话自助管理与设备标识

- 登录请求可带可选字段 `device`（设备/客户端说明，字符串），**不传也正常工作**，
  会话记录中该字段为空字符串。
- 每个会话保存：`session_id`（会话标识）、`created_at`（创建时间）、
  `last_refreshed_at`（最近一次刷新时间，创建时取创建时间，每次成功刷新更新）、
  `status`（当前状态）、`device`（设备说明）。
- `GET /sessions`（凭访问令牌）返回**当前用户所有仍有效会话**，按创建时间升序。
- `POST /sessions/{session_id}/revoke`：撤销自己的某一个会话。
  撤销后**仅该会话的访问令牌与其刷新链路立即失效**，其他会话不受影响；
  撤销**当前会话**会被明确拒绝（`403 forbidden`，当前会话请用登出）。
- `POST /sessions/revoke-others`：一次撤销**除当前会话外**的本人全部其他会话，
  返回被撤销的会话标识列表；当前会话保证不被误撤销，其他用户会话不受影响。
- 越权保护：用户只能查询/撤销**自己的**会话。对他人会话标识的操作统一返回
  `401 session_not_found`，不泄漏他人会话是否存在。

### 并发会话容量限制

- 同一用户同时有效的会话数有上限，**默认 5 个**，按用户独立计数。
- 调整方式：构造 `AuthService(max_sessions_per_subject=N, ...)`
  （`app/main.py` / `app/api.py` 的 `create_app(service=...)` 可注入自定义实例）。
- 达到上限后的新登录：
  - **不静默挤掉旧会话**，也**不留下半成功状态**——容量检查在会话存储单把锁内、
    创建动作之前完成，被拒时既不建会话也不签发任何令牌，因此不存在"被拒但令牌可用"。
  - 返回**明确、可区分且稳定**的结果：HTTP `409`，错误码 `session_limit_reached`。
  - 多个登录请求并发到达时，锁内计数保证**最终有效会话数绝不超过上限**；
    成功/失败结果与最终状态一致（N 个成功各拿到可用令牌，其余全部 409）。
- 登出 / 撤销 / 重放终止会释放容量，腾出位置后可再次登录。

## 安全审计

- 以下动作都会被记录，每条记录包含 `seq`（全局单调序号）、`timestamp`、
  `subject`（主体）、`session_id`（适用时）、`action`（动作）、
  `result`（判定结果/原因）、`detail`：

  | 动作 `action` | 触发时机 |
  | --- | --- |
  | `login` / `login_rejected` | 登录成功 / 登录被拒（**含容量限制拒绝**，此时无会话标识） |
  | `refresh` / `refresh_rejected` | 刷新成功 / 刷新被拒（过期、重放、密钥轮换失效等，带原因） |
  | `logout` | 主动登出 |
  | `session_revoke` | 单会话撤销 |
  | `sessions_revoke_others` | 批量撤销其他会话 |
  | `session_terminated` | 会话因**异常刷新**（刷新令牌重放）而终止 |
  | `key_rotate` | 签名密钥轮换 |
  | `role_permissions_change` | 角色权限调整 |

- **保留与清理**：审计日志为本地内存有界队列，`AuthService(audit_max_entries=N)`
  可配容量（默认 10000 条，最小为 1）；**超过上限丢弃最旧记录**
  （有界 deque，内存占用可预期，不会无限增长）。
- **并发写入**：所有写入在同一把锁内分配全局递增 `seq` 并入队，
  并发写入不会丢失或重复。
- **查询**：`GET /sessions` 同级的 `GET /audit`，支持参数
  `subject`、`action`、`start`、`end`（epoch 秒，闭区间）、`offset`、`limit`；
  返回 `total`（满足过滤条件的总数）与当前页 `items`。
  排序稳定：**时间升序，同一时间按 `seq` 升序**；分页基于序号切片，翻页不重不漏。
- **权限范围**：
  - 普通用户（任何有效登录）只能查询**自己的**记录——即使请求带了他人的
    `subject` 参数，服务端也强制收敛为本人。
  - 具备 `session:manage` 权限点的角色可查询**全部**记录，并按
    用户 / 动作 / 时间范围过滤与分页。

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
| `session_not_found` | 401 | 会话不存在（或访问/操作他人会话，不泄漏存在性） |
| `session_limit_reached` | 409 | 并发会话数已达上限，登录被拒绝（无半成功状态） |
| `forbidden` | 403 | 已认证但缺少权限，或尝试撤销当前会话 |
| `resource_not_found` | 404 | 授权通过但资源不存在 |

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
# 登录（device 可选；同一用户第 6 个并发登录将返回 409 session_limit_reached）
curl -s -X POST localhost:8000/login -H 'content-type: application/json' \
  -d '{"subject":"alice","roles":["reader"],"device":"iPhone 17"}'

# 访问受保护资源
curl -s localhost:8000/resources/doc-1 -H "Authorization: Bearer <access_token>"

# 刷新（再次提交同一刷新令牌将触发重放检测）
curl -s -X POST localhost:8000/refresh -H 'content-type: application/json' \
  -d '{"refresh_token":"<refresh_token>"}'

# 查看自己当前的有效会话（标识/创建时间/最近刷新/状态/设备）
curl -s localhost:8000/sessions -H "Authorization: Bearer <access_token>"

# 撤销自己的另一个会话（撤销当前会话会得到 403）
curl -s -X POST localhost:8000/sessions/<other_session_id>/revoke \
  -H "Authorization: Bearer <access_token>"

# 撤销除当前会话外的其他会话
curl -s -X POST localhost:8000/sessions/revoke-others \
  -H "Authorization: Bearer <access_token>"

# 查询审计（普通用户仅返回本人；具备 session:manage 可用 subject/action/start/end 过滤）
curl -s "localhost:8000/audit?action=login&offset=0&limit=20" \
  -H "Authorization: Bearer <access_token>"
```

容量与审计保留条数可在构造服务时本地调整：

```python
from app.api import create_app
from app.service import AuthService

svc = AuthService(max_sessions_per_subject=3, audit_max_entries=5000)
app = create_app(svc)
```

测试覆盖：并发刷新（32 线程仅 1 成功）、刷新令牌重放并撤销会话族、
登出 / 撤销 / 密钥轮换后继续使用、权限调整立即生效、越权不泄漏资源存在性、
各类失败原因可区分；以及**并发登录触及容量上限（32 线程恰 5 成功、
拒绝返回稳定 409 且不残留可用令牌）、设备标识与会话列表、单会话与批量撤销隔离、
当前会话保护、跨用户会话/审计越权被拒、审计并发写入不丢不重、有界容量丢弃最旧、
过滤 / 稳定排序 / 分页、普通用户与特权角色的审计查询范围**（见 `tests/test_sessions.py`）。
