# identity-access-control-python

本仓库在 FastAPI 后端之上实现了一套**服务自身的身份认证与会话访问控制能力**：
令牌签发 / 刷新 / 撤销 / 授权判定全部在本地完成，仅依赖 Python 标准库
（HMAC-SHA256 签名），不依赖外部身份服务或真实凭据。

## 架构

| 模块 | 职责 |
| --- | --- |
| `app/errors.py` | 可区分的失败原因 `DenyReason` 与 `AuthError` |
| `app/tokens.py` | 类 JWT 令牌编解码（HMAC-SHA256）、`KeyRing` 签名密钥轮换 |
| `app/sessions.py` | 会话与刷新令牌族存储：一次性轮换、重放检测、撤销 |
| `app/authz.py` | RBAC：角色 → `资源:操作` 权限点，授权判定 |
| `app/service.py` | `AuthService` 门面：登录、刷新、登出、撤销、密钥轮换、授权 |
| `app/api.py` | FastAPI HTTP 入口，错误到状态码的映射 |

## 令牌生命周期

- 令牌格式：`base64url(header).base64url(payload).base64url(hmac_sha256)`，
  header 携带 `kid` 标识签名密钥。
- **签发**：`POST /login` 返回访问令牌（默认 300s）与刷新令牌（默认 3600s），
  同时创建会话（一个会话对应一个刷新令牌族）。
- **刷新**：`POST /refresh` 提交刷新令牌，服务端**一次性轮换**——
  旧刷新令牌立即作废，签发新一代令牌对。
- **登出**：`POST /logout`（Bearer 访问令牌）使会话失效。
- **撤销**：`POST /sessions/{id}/revoke`（需 `session:revoke` 权限）主动使会话失效。

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
| `forbidden` | 403 | 已认证但缺少权限（不泄漏资源存在性） |
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
# 登录（角色需在服务侧已配置权限，见 tests/ 与 app/api.py 示例）
curl -s -X POST localhost:8000/login -H 'content-type: application/json' \
  -d '{"subject":"alice","roles":["reader"]}'

# 访问受保护资源
curl -s localhost:8000/resources/doc-1 -H "Authorization: Bearer <access_token>"

# 刷新（再次提交同一刷新令牌将触发重放检测）
curl -s -X POST localhost:8000/refresh -H 'content-type: application/json' \
  -d '{"refresh_token":"<refresh_token>"}'
```

测试覆盖：并发刷新（32 线程仅 1 成功）、刷新令牌重放并撤销会话族、
登出 / 撤销 / 密钥轮换后继续使用、权限调整立即生效、越权不泄漏资源存在性、
各类失败原因可区分。
