# 服务自身身份认证与会话访问控制（本地化）

在 FastAPI 骨架之上实现的一套**进程内、零外部依赖**的身份认证与会话访问控制能力：
令牌签发 / 刷新（一次性轮换）/ 撤销 / 操作级授权判定，在并发与异常场景下结果一致、
原因可解释。不依赖任何外部身份服务或真实凭据，全部状态保存在本地内存。

## 1. 目录结构

| 文件 | 职责 |
| --- | --- |
| `main.py` | 服务入口：`uvicorn main:app`，装配默认服务与种子数据 |
| `auth/app.py` | FastAPI 路由、HTTP 状态码映射、资源存在性隐藏、种子用户 |
| `auth/service.py` | 核心：登录 / 刷新 / 登出 / 撤销 / 密钥轮换 / 校验 / 授权 |
| `auth/store.py` | 本地内存状态：用户、角色权限、会话族、刷新/访问令牌记录（单锁保护） |
| `auth/keys.py` | HMAC-SHA256 签名密钥：任意时刻仅一把活动密钥，轮换即丢弃旧密钥 |
| `auth/tokens.py` | JWT 风格访问令牌（`header.payload.signature`）的编码与结构解析 |
| `auth/policy.py` | 操作级 RBAC：`资源:操作` 精确/通配匹配，判定结果可解释 |
| `auth/security.py` | PBKDF2 口令哈希（恒定时间比较）与密码学随机标识 |
| `auth/errors.py` | `DenyReason` 拒绝原因枚举与 `AuthError` |
| `auth/audit.py` | 结构化审计日志（令牌只记 SHA-256 指纹，不记原文） |
| `tests/` | 38 个单测，含真实线程并发刷新、重放、撤销、即时授权等场景 |

## 2. 令牌生命周期

### 2.1 令牌类型

- **访问令牌（access token）**：JWT 风格紧凑串，header 携带 `kid`，payload 含
  `sub / sid（会话族 id）/ jti / iat / exp`，HMAC-SHA256 签名。默认有效期 15 分钟。
  除无状态验签外，服务端还为每个 jti 保存存活记录。
- **刷新令牌（refresh token）**：不透明随机串（32 字节 urlsafe），**只存服务端**，
  从不自我描述。默认有效期 7 天。

### 2.2 登录与会话族

`POST /auth/login` 成功后创建一个**会话族（family）**并签发第一对令牌。
一个族对应一次登录；族内刷新令牌构成单链：`r0 → r1 → r2 …`。

### 2.3 刷新：一次性轮换（rotation）

`POST /auth/refresh` 的全部判定在 `LocalStore` 的同一把可重入锁内**原子**完成：

1. 刷新令牌不认识 → `refresh_unknown`；
2. **已使用过或已撤销** → `refresh_replay`，并**撤销整个会话族**
   （族内所有刷新令牌与访问令牌立即失效）——这是刷新令牌被盗后重放的标准处置；
3. 族已撤销 → `family_revoked`；
4. 已过期 → `token_expired`，并撤销整族；
5. 否则：旧刷新令牌置 `used`，原子签发新一对令牌并替换族的当前刷新令牌。

**并发语义**：同一刷新令牌被并发提交时（临界区原子），**恰好一个请求成功**，
其余请求都得到明确的 401（`refresh_replay` / 族撤销后可能为 `family_revoked`）。
落败请求的重放判定会撤销整族，因此即使是“赢家”返回的新凭据也立即失效——
**绝不会出现两份同时生效的凭据**。`tests/test_session_lifecycle.py` 与
`tests/test_api.py` 分别在服务层（32 线程）和真实 HTTP 线程（16 线程）断言这一点。

### 2.4 登出与主动撤销

- `POST /auth/logout`：撤销该会话族——族内所有访问令牌的 jti 立即从存活集合摘除，
  刷新令牌全部撤销。访问令牌**不等待自然过期**，在其原始有效期内也立即失效。
- `POST /admin/sessions/{family_id}/revoke`：管理员主动撤销指定会话族，语义相同。

### 2.5 密钥轮换

`POST /admin/keys/rotate`（需 `admin:rotate_keys` 权限）生成新的 HMAC 密钥与 `kid`，
**立即丢弃旧密钥**（不保留旧密钥用于验证）。此后所有旧访问令牌在校验时因
`kid` 非当前活动密钥被拒绝，原因码 `key_not_active`——同样不等待令牌过期。

### 2.6 访问令牌校验顺序（全部实时、无缓存）

1. `Authorization` 头存在且为 `Bearer <token>` —— 否则 `missing_credential`；
2. 结构可解析 —— 段数/base64/JSON/header/claims 非法为 `malformed_token`；
3. `kid` 为当前活动密钥 —— 否则 `key_not_active`；
4. 签名匹配（恒定时间比较）—— 否则 `bad_signature`；
5. `exp` 未过 —— 否则 `token_expired`；
6. jti 仍存活 —— 否则 `access_token_revoked`；
7. 会话族未撤销 —— 否则 `family_revoked`；
8. 用户仍启用 —— 否则 `user_disabled`。

## 3. 授权模型（操作级 RBAC）

- 权限标识为 `资源:操作`，如 `doc:read`、`doc:publish`、`admin:rotate_keys`；
- 匹配规则：精确匹配；`doc:*` 匹配该资源下任意操作；`*` 为全局通配；
- 用户可拥有多个角色，权限取并集；
- 角色 → 权限集合保存在内存，授权判定**每次实时读取，不做缓存**，
  因此权限新增/移除在调用方的**下一次请求**即生效，无需重新登录或等待过期；
- 判定返回结构化 `Decision(allowed, username, operation, matched_permissions, reason)`，
  并通过 `auth/audit.py` 打印“输入 + 判定依据”。

### 资源存在性隐藏

对资源类接口，“已认证但无权操作”与“资源不存在”返回**完全相同**的
`404 {"error":"not_found","error_description":"资源不存在或无权访问"}`，
不泄漏目标资源是否存在。真正的拒绝原因（`forbidden_operation`）保留在服务层
返回值与审计日志中。

> 注意区分：凭据类问题（缺失 / 格式错误 / 失效 / 撤销）仍返回 401 且携带精确原因码；
> 仅“凭据有效但授权不足”在资源接口上被伪装成 404。管理类接口（如密钥轮换）的
> 授权不足返回 403。

### 拒绝原因码对照（`auth/errors.py: DenyReason`）

| 原因码 | 含义 | HTTP |
| --- | --- | --- |
| `missing_credential` | 缺少凭据 | 401 |
| `malformed_token` | 凭据格式错误 | 401 |
| `bad_signature` | 签名不匹配（凭据被伪造/篡改） | 401 |
| `key_not_active` | 签名密钥已轮换，旧令牌立即失效 | 401 |
| `token_expired` | 令牌已过期 | 401 |
| `access_token_revoked` | 访问令牌被登出/主动撤销 | 401 |
| `session_revoked` / `family_revoked` | 会话/会话族已撤销 | 401 |
| `refresh_replay` | 刷新令牌已使用过（含并发落败者），整族已撤销 | 401 |
| `refresh_unknown` | 刷新令牌不认识 | 401 |
| `invalid_credentials` | 登录用户名或口令错误（不区分用户是否存在） | 401 |
| `user_disabled` | 账户已禁用 | 401 |
| `forbidden_operation` | 凭据有效但无权执行该操作 | 403 / 资源接口伪装 404 |

## 4. HTTP 接口

| 方法与路径 | 所需操作权限 | 说明 |
| --- | --- | --- |
| `POST /auth/login` | — | 体 `{username,password}`，返回访问/刷新令牌 |
| `POST /auth/refresh` | — | 体 `{refresh_token}`，一次性轮换 |
| `POST /auth/logout` | — | 撤销整族；令牌取 Authorization 头或体 `{access_token}` |
| `POST /admin/keys/rotate` | `admin:rotate_keys` | 密钥轮换，旧访问令牌立即失效 |
| `POST /admin/roles/{role}/permissions` | `admin:manage_roles` | 体 `{permission}`，下一次请求生效 |
| `DELETE /admin/roles/{role}/permissions/{permission}` | `admin:manage_roles` | 移除权限，下一次请求生效 |
| `POST /admin/sessions/{family_id}/revoke` | `admin:revoke_session` | 主动撤销会话族 |
| `GET /resources/{id}` | `doc:read` | 越权与不存在均返回相同 404 |
| `POST /resources/{id}/publish` | `doc:publish` | 同上 |
| `GET /health` | — | 健康检查 |

内置种子账户（仅本地演示）：

| 用户 | 口令 | 角色 / 权限 |
| --- | --- | --- |
| `alice` | `alice-pw` | editor + viewer：`doc:read`、`doc:publish` |
| `bob` | `bob-pw` | viewer：`doc:read` |
| `root` | `root-pw` | admin：`*` |

## 5. 并发一致性与可解释性如何保证

- **单存储锁**：`LocalStore.lock`（可重入）覆盖刷新轮换、撤销、状态判定的读改写；
  刷新路径上“判定 + 置 used + 换发 + 替换族当前令牌”不可分割。
- **无判定缓存**：访问令牌 jti 存活集、族撤销标志、用户启用状态、角色权限均在每次
  请求时实时读取，因此撤销与权限调整不存在因缓存/时序导致的短暂放行窗口。
- **密钥即边界**：密钥管理器只保留当前密钥，轮换 = 生成 + 丢弃，旧令牌统一在
  `kid` 检查处失败。
- **可解释**：所有拒绝都映射到唯一 `DenyReason`；每次判定经 `audit.audit` 输出
  结构化日志（事件、输入用户/操作、令牌指纹、判定依据 `Decision.explain()`）。
  测试中同样使用 `logging` 打印输入与判定依据。

## 6. 本地验证方法

需要 Python ≥ 3.14 与 [uv](https://docs.astral.sh/uv/)。

```bash
# 安装依赖（含 pytest）
uv sync
uv add --dev pytest   # 如尚未安装

# 运行全部单测（38 个），日志中可见输入与判定依据
uv run pytest -q -s

# 仅跑并发刷新场景
uv run pytest -q \
  tests/test_session_lifecycle.py::test_concurrent_refresh_only_one_succeeds \
  tests/test_api.py::test_http_concurrent_refresh_single_winner

# 多轮重复验证并发结果稳定
for i in $(seq 1 10); do
  uv run pytest -q tests/test_session_lifecycle.py::test_concurrent_refresh_only_one_succeeds
done

# 启动服务
uv run uvicorn main:app --reload
# 交互式文档：http://127.0.0.1:8000/docs
```

手工冒烟：

```bash
# 1. 登录
TOK=$(curl -s -X POST localhost:8000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice-pw"}')
ACCESS=$(python -c "import sys,json;print(json.loads('''$TOK''')['access_token'])")
REFRESH=$(python -c "import sys,json;print(json.loads('''$TOK''')['refresh_token'])")

# 2. 访问受保护资源
curl -s localhost:8000/resources/doc-1 -H "Authorization: Bearer $ACCESS"

# 3. 刷新（一次性轮换）
curl -s -X POST localhost:8000/auth/refresh \
  -H 'Content-Type: application/json' -d "{\"refresh_token\":\"$REFRESH\"}"

# 4. 再次用旧 refresh -> 401 refresh_replay，且整族撤销
curl -s -X POST localhost:8000/auth/refresh \
  -H 'Content-Type: application/json' -d "{\"refresh_token\":\"$REFRESH\"}"

# 5. bob 越权 publish 与资源不存在返回完全一致的 404
BOB=$(curl -s -X POST localhost:8000/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"bob","password":"bob-pw"}' | python -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
curl -si -X POST localhost:8000/resources/doc-1/publish -H "Authorization: Bearer $BOB"
curl -si localhost:8000/resources/nope -H "Authorization: Bearer $BOB"
```

## 7. 范围说明

本实现面向“服务自身”的本地认证授权演示：状态为进程内存存储（重启即清空），
密钥不出进程，不使用真实第三方身份服务。刷新令牌重放采用严格处置
（任何重放即整族撤销，并发刷新落败者同样触发），这是有意的安全取舍。
