# HTTP 消息签名验收 API

基于 **RFC 9421（HTTP Message Signatures）** 的服务端签名验收服务。管理员登记签名者公钥版本并配置验收策略；客户端提交一条 HTTP 请求的方法、目标 URI、**有序原始头字段**、正文以及 `Signature-Input` / `Signature`，服务将：

1. 按 **RFC 8941 Structured Fields**（`http-sfv`）解析 `Signature-Input` / `Signature`（支持 RFC 9421 的字符串标签 `"sig1"=` 与裸键两种字典键）；
2. 重建派生组件（`@method`、`@target-uri`、`@authority`、`@scheme`、`@path`、`@query`、`@query-param;name=`、`@request-target`）与签名基串（RFC 9421 §2.5），逐字段做遗留（legacy）或 Structured Field 规范化；
3. 校验 **Content-Digest（RFC 9530，sha-256 / sha-512）** 与正文一致；
4. 校验 `created`（未来时钟偏差 `clock_skew`、最长有效期 `max_age`）、`expires`、`nonce`、必签组件、允许的算法等策略；
5. 用登记的公钥验签：**Ed25519**、**RSA-PSS-SHA256**、**RSA-PSS-SHA512**（`cryptography`）；
6. 验签成功后，**在同一数据库事务内**按 `(keyid, nonce)` 原子插入防重放记录，并**签发可离线核验的验收回执**（服务端 Ed25519 密钥签名的版本化规范载荷，与 nonce 占用同事务持久化）：并发重复提交恰有一次 `accepted`、至多一份回执，其余全部 `409 replayed`。

此外，验收策略是**不可变版本化**的：管理员可以当前激活策略为基线创建草稿、做并发安全的原子激活；还提供**影子验签**接口 `/verify-shadow`，按任意历史/草稿策略版本完整执行全部校验，但**绝不写入 `used_nonces`、绝不改变正式验收状态**，并返回相对当前激活版本的逐项差异。

每份验收回执还可以被**幂等撤销**：管理员在单个数据库事务内按 `receipt_id` 提交带 `reason` / `effective_at` / `expected_revision` 的撤销命令；服务锁定回执、拒绝未知回执与冲突命令，生成**不可变、带全局序号、服务端 Ed25519 签名**的撤销记录，并与一条**哈希链式审计记录**原子提交。新增**按时点查询**接口，返回回执 `valid` / `revoked` / `unknown` 状态及签名撤销证明；离线工具可同时核验回执、**历史公钥**与撤销证明，任何篡改、时间倒流或跨回执复用都会失败。

验签成功响应中包含密钥版本、SPKI 指纹、逐组件值、完整签名基串（单行与整体）、执行所用策略版本、稳定原因码，以及一份**服务端签名、可离线核验的验收回执**（见下文「验收回执」）。

> 互操作性：本实现重建的签名基串及 Ed25519 签名与 RFC 9421 附录 B.2.6 **逐字节一致**，并能验证附录 B.2.2 的官方 RSA-PSS-SHA512 签名（见 `tests/test_rfc_vectors.py`）。

## 技术栈

| 组件 | 选择 |
| --- | --- |
| 语言/框架 | Python 3.11 + FastAPI + Uvicorn |
| 数据库 | PostgreSQL 16（`psycopg2` 连接池） |
| Structured Fields | [`http-sfv`](https://pypi.org/project/http-sfv/) 0.9.x |
| 密码学 | [`cryptography`](https://cryptography.io/)（Ed25519 / RSA-PSS） |
| 校验 | Pydantic v2 |

## 一键启动（Docker Compose）

需要 Docker 20+ 与 Docker Compose v2。

```bash
docker compose up --build
```

启动后：

- API：<http://localhost:8000>
- Swagger UI：<http://localhost:8000/docs>
- 健康检查：`GET http://localhost:8000/health`
- PostgreSQL：`localhost:5432`（用户/密码/库均为 `hss`）

回执能力随一键启动自动就绪：首次启动时服务自动生成服务端 Ed25519 回执签名密钥（v1）并持久化在 PostgreSQL 中（`pgdata` 卷，重启后保留；私钥不通过任何 API 暴露），无需额外配置。

可用环境变量（在 `.env` 或 shell 中设置）：

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `DATABASE_URL` | `postgresql://hss:hss@db:5432/hss` | PostgreSQL DSN |
| `ADMIN_TOKEN` | `admin-secret` | 管理接口令牌（`X-Admin-Token` 头）；置空可关闭鉴权 |
| `DB_CONNECT_RETRIES` | `30` | 启动时连接数据库重试次数 |
| `DB_CONNECT_DELAY` | `1.0` | 重试间隔秒数 |

停止与清理：

```bash
docker compose down          # 停止
docker compose down -v       # 停止并删除数据库卷
```

## 管理 API

所有 `/admin/*` 接口需要请求头 `X-Admin-Token: <ADMIN_TOKEN>`。

### 登记公钥（新版本）

`POST /admin/keys`

同一 `keyid` 重复登记会自动停用旧版本、版本号 +1（部分唯一索引保证每个 `keyid` 至多一个启用版本，登记过程在事务内加 advisory lock）。公钥支持：

- PEM（SubjectPublicKeyInfo `-----BEGIN PUBLIC KEY-----`）；
- base64 编码的 DER SPKI；
- base64 编码的 32 字节裸 Ed25519 公钥。

```bash
# 从 PEM 文件登记
curl -sX POST http://localhost:8000/admin/keys \
  -H "X-Admin-Token: admin-secret" -H 'Content-Type: application/json' \
  -d "{\"keyid\":\"key-1\",\"public_key\":$(jq -Rs . < public.pem)}"
```

```json
{
  "keyid": "key-1",
  "version": 1,
  "key_kind": "ed25519",
  "fingerprint": "b17012e9cc70f2b070459a67372337ac9575a4a0d96639162345784fe8ae2a9b",
  "enabled": true,
  "id": 1,
  "created_at": "2026-09-22T18:17:12.013818+00:00"
}
```

### 配置验收策略（现行单例）

`GET/PUT /admin/policy`

> 该接口是 v1 兼容入口。每次 `PUT` 都会在版本历史中原子生成一个**新的不可变激活版本**（旧激活版本转为 `retired`），因此不会绕过版本化。需要评审/灰度流程时请改用下面的草稿与激活接口。

```json
{
  "required_components": ["@method", "@target-uri", "@authority", "content-digest"],
  "required_algorithms": ["ed25519", "rsa-pss-sha256", "rsa-pss-sha512"],
  "clock_skew_seconds": 30,
  "max_age_seconds": 300,
  "require_created": true,
  "require_nonce": true,
  "require_content_digest_with_body": true
}
```

GET 响应额外含 `version`（当前激活版本号）与 `activated_at`。

### 策略版本化：草稿与原子激活

每条策略版本都是 `policy_versions` 表中的**不可变快照**，状态机为：

```
draft ──activate──> active（同时旧 active 变 retired）
```

数据库用部分唯一索引保证任意时刻**至多一个 active**；激活在 advisory lock 内一步完成（旧版本退役、草稿激活、单例镜像刷新在同一事务），并带**乐观并发基线校验**：基线过期时整体回滚并返回 `409 policy_activation_conflict`。

| 接口 | 说明 |
| --- | --- |
| `GET /admin/policy/versions?status=draft\|active\|retired` | 列出全部版本（可按状态过滤），响应含 `active_version` |
| `GET /admin/policy/versions/{version}` | 查询单个不可变版本（重启后结果一致） |
| `POST /admin/policy/drafts` | 基于当前激活版本创建不可变草稿 |
| `POST /admin/policy/versions/{version}/activate` | 原子激活草稿 |

**创建草稿**：请求体中所有字段都可省略，省略即克隆当前激活版本；可选 `baseline_version` 用于并发保护。草稿记录全部验收参数：必签组件、允许算法、时钟偏差、最长有效期及各开关，另有 `baseline_version` 记录其基线。

```bash
curl -sX POST http://localhost:8000/admin/policy/drafts \
  -H "X-Admin-Token: admin-secret" -H 'Content-Type: application/json' -d '{
    "baseline_version": 1,
    "required_components": ["@method", "@target-uri", "@authority", "content-digest"],
    "required_algorithms": ["ed25519"],
    "clock_skew_seconds": 30,
    "max_age_seconds": 600,
    "require_created": true,
    "require_nonce": true,
    "require_content_digest_with_body": true
  }'
```

```json
{
  "version": 2,
  "status": "draft",
  "baseline_version": 1,
  "required_components": ["@method", "@target-uri", "@authority", "content-digest"],
  "required_algorithms": ["ed25519"],
  "clock_skew_seconds": 30,
  "max_age_seconds": 600,
  "require_created": true,
  "require_nonce": true,
  "require_content_digest_with_body": true,
  "created_at": "2026-09-23T10:00:00+00:00",
  "activated_at": null
}
```

**激活草稿**（可选请求体 `{"expected_active_version": 1}`；省略时以草稿的 `baseline_version` 为准）：

```bash
curl -sX POST http://localhost:8000/admin/policy/versions/2/activate \
  -H "X-Admin-Token: admin-secret" -H 'Content-Type: application/json' -d '{}'
```

冲突时（别的管理员已先激活了其它草稿）：

```json
{
  "detail": {
    "reason": "policy_activation_conflict",
    "detail": "cannot activate version 3: active version is 2 but the change was based on version 1",
    "active_version": 2
  }
}
```

其他管理接口：`GET /admin/keys`（列出全部版本）、`POST /admin/keys/{keyid}/disable|enable`。

## 验收接口

`POST /verify`

**请求体**（注意 `headers` 必须保持传输时的原始顺序；重复头字段按顺序全部给出）：

```json
{
  "method": "POST",
  "target_uri": "https://api.example.com/demo?x=1",
  "headers": [
    {"name": "content-type", "value": "application/json"},
    {"name": "content-digest", "value": "sha-256=:x/0NWO31kgQud7dL+x8w7QvrLatt0WFm/fxq6C0EFrM=:"}
  ],
  "body": "eyJoZWxsbyI6IndvcmxkIiwibiI6NDJ9",
  "signature_input": "sig1=(\"@method\" \"@target-uri\" \"@authority\" \"content-digest\" \"content-type\");keyid=\"key-1\";alg=\"ed25519\";created=1790101132;nonce=\"dkHMsQDdYntJZCnnYFffog\"",
  "signature": "sig1=:9eG1...base64...=:"
}
```

字段说明：

| 字段 | 说明 |
| --- | --- |
| `method` | 被签名请求的方法（规范化时转大写） |
| `target_uri` | 绝对目标 URI（含 scheme/host/path/query） |
| `headers` | 有序原始头字段，元素为 `{"name","value"}` 或 `[name, value]` |
| `body` | 正文，标准 base64；无正文传 `null` |
| `signature_input` / `Signature-Input` | 原始 `Signature-Input` 字段值（两种键名都接受） |
| `signature` / `Signature` | 原始 `Signature` 字段值 |

**成功响应 `200`**（含密钥版本、逐组件值、签名基串与验收回执）：

```json
{
  "status": "accepted",
  "keyid": "key-1",
  "key_version": 3,
  "key_fingerprint": "e3a6a44540956c2d7517be62df399a34bc174a52beafbdd0fd9bcf5958662d93",
  "label": "sig1",
  "algorithm": "ed25519",
  "created": 1790101132,
  "expires": null,
  "nonce": "dkHMsQDdYntJZCnnYFffog",
  "components": {
    "\"@method\"": "POST",
    "\"@target-uri\"": "https://api.example.com/demo?x=1",
    "\"@authority\"": "api.example.com",
    "\"content-digest\"": "sha-256=:x/0NWO31kgQud7dL+x8w7QvrLatt0WFm/fxq6C0EFrM=:",
    "\"content-type\"": "application/json",
    "@signature-params": "(\"@method\" ... );keyid=\"key-1\";alg=\"ed25519\";created=..."
  },
  "signature_base": "\"@method\": POST\n...\n\"@signature-params\": (...)",
  "signature_base_lines": ["\"@method\": POST", "..."],
  "receipt": {
    "receipt_id": "d56b60a2-078c-4443-8863-8ad2f05643db",
    "key_id": "receipt-signing#1",
    "issued_at": "2026-09-25T12:34:56.789012+00:00",
    "issued_at_unix": 1790301296,
    "payload": "receipt/v1\nreceipt_id: d56b60a2-...\nkey_id: receipt-signing#1\nissued_at: 1790301296\nkeyid: key-1\nkey_version: 3\npolicy_version: 1\nalgorithm: ed25519\nlabel: sig1\nnonce: dkHMsQDdYntJZCnnYFffog\ninput_digest: sha256:0iuiS2Ns+...=",
    "payload_sha256": "dde7138e1cad9052bd0bafd8ed18c1180eda8fa14cd709385d6d88f824fe86ed",
    "signature": "FMz3lTBpnnDXcFqIt0CVutahaHuSl4mIn4hmdEqZ/CSHfoHCYKrAkwiyck1iFd9IHScxWLo29TIB/pJ75rpACg==",
    "input_digest": "sha256:0iuiS2Ns+...=",
    "context": {
      "keyid": "key-1",
      "key_version": 3,
      "policy_version": 1,
      "algorithm": "ed25519",
      "label": "sig1",
      "nonce": "dkHMsQDdYntJZCnnYFffog"
    }
  }
}
```

`receipt` 之外的响应字段与回执模块引入前完全一致；回执的语义与离线核验方式见下文「验收回执」。

**重放响应 `409`**（相同 `keyid + nonce` 再次提交；并发下也只可能有一次成功）：

```json
{
  "status": "replayed",
  "reason": "replayed",
  "detail": "nonce 'dkH...' for keyid 'key-1' has already been accepted",
  "keyid": "key-1",
  "key_version": 3,
  "key_fingerprint": "…",
  "algorithm": "ed25519",
  "label": "sig1",
  "nonce": "dkH..."
}
```

## 影子验签接口

`POST /verify-shadow`

请求体与 `/verify` **完全相同**，额外增加一个必填整数字段 `policy_version`。服务按该版本（`draft` / `active` / `retired` 均可）完整执行与 `/verify` 相同的校验链：

- RFC 9421 `Signature-Input` / `Signature` 解析与标签检查；
- 签名基串重建与逐组件规范化；
- RFC 9530 Content-Digest 与密钥解析（当前启用的密钥版本）；
- 新鲜度（`created` / `expires` / `clock_skew` / `max_age`）、必签组件、允许算法；
- Ed25519 / RSA-PSS 密码学验签。

但它运行在**只读事务**中：

1. **绝不写入 `used_nonces`**——影子调用可以无限次重放同一 nonce；
2. **绝不改变正式验收状态**——不影响之后 `/verify` 的任何结果；
3. 若该 nonce 已被正式验收消费过，仅在响应中以 `nonce_seen: true` 作**提示**，不构成失败（HTTP 仍为 200）。

响应在 `/verify` 字段之外附带版本与差异信息：

| 字段 | 说明 |
| --- | --- |
| `status` | 成功为 `shadow_accepted`；失败为 `rejected` / `replayed`（原因码同 `/verify`） |
| `policy_version` / `policy_status` | 实际执行的版本号及其状态（draft/active/retired） |
| `active_policy_version` | 当前正式激活版本号 |
| `diff_vs_active` | 该版本相对当前激活版本的**逐项差异**（见下） |
| `diff_count` | 差异项数量（激活版本自身为 0） |
| `nonce_seen` | 该 `(keyid, nonce)` 是否已被正式验收消费（仅提示） |

`diff_vs_active` 中每个元素只描述一个字段，键序固定：

```json
{
  "active_policy_version": 1,
  "policy_status": "draft",
  "policy_version": 2,
  "diff_count": 2,
  "diff_vs_active": [
    {
      "field": "required_algorithms",
      "kind": "set",
      "active": ["ed25519", "rsa-pss-sha256", "rsa-pss-sha512"],
      "candidate": ["ed25519"],
      "added": [],
      "removed": ["rsa-pss-sha256", "rsa-pss-sha512"],
      "changed": true
    },
    {
      "field": "max_age_seconds",
      "kind": "scalar",
      "active": 300,
      "candidate": 600,
      "changed": true
    }
  ],
  "nonce_seen": false
}
```

校验失败时响应体与 `/verify` 使用同一套**稳定原因码**和 HTTP 状态映射，同时同样附带上面的版本/差异字段；版本不存在返回 `404 policy_version_unknown`。典型用途：先建草稿 → 对生产流量样本调 `/verify-shadow` 评估影响 → 再原子激活。

> 一致性：版本快照与差异全部由 PostgreSQL 持久化、无进程内缓存，因此版本查询结果与影子验签结论在多次调用之间、以及**应用重启之后**完全一致。

### 稳定原因码

`reason` 字段在版本间保持稳定，便于客户端编程处理。HTTP 状态码：4xx 表示请求/策略/密码学问题（`replayed` 为 409，未知 key 为 404，其余多为 401/400）。

| reason | 含义 |
| --- | --- |
| `bad_request` / `body_not_base64` | 请求信封格式错误 |
| `malformed_signature_input` / `malformed_signature` | SF 解析失败 |
| `label_mismatch` / `multiple_signatures` | 标签不一致 / 提交了多个签名 |
| `unknown_key` / `key_disabled` | keyid 无启用版本 / 已停用 |
| `invalid_public_key` | 登记公钥损坏或与算法族不符 |
| `algorithm_unsupported` / `algorithm_not_allowed` | 算法不支持 / 被策略禁止 |
| `required_component_missing` | 缺少策略要求必签的组件 |
| `content_digest_required` / `content_digest_missing` / `content_digest_unsupported` / `content_digest_mismatch` | Content-Digest 各类失败 |
| `invalid_component` / `invalid_component_parameter` / `unknown_component` / `component_value_unavailable` / `duplicate_component` / `related_request_unsupported` | 组件重建失败 |
| `created_in_future` / `message_expired` / `message_age_exceeded` / `created_required` | 新鲜度策略失败 |
| `signature_invalid` | 密码学验签失败 |
| `replayed` | `(keyid, nonce)` 已被使用 |
| `policy_version_unknown` | 指定的策略版本不存在 |
| `policy_activation_conflict` | 草稿基线已过期（并发激活冲突），需 rebase |
| `policy_draft_not_activatable` | 激活目标不是草稿（已激活或已退役） |
| `receipt_unknown` | 按 ID 查询的回执不存在（404） |
| `receipt_issuance_failed` | 回执签发或持久化失败，验收整体回滚（500，nonce 未被消费，可安全重试） |
| `receipt_already_revoked` | 回执已撤销且本次命令内容不同（409；相同命令为 200 幂等） |
| `revocation_revision_conflict` | `expected_revision` 与回执当前修订号不符（409） |
| `revocation_effective_before_issuance` | 撤销生效时刻早于回执签发时刻（时间倒流，409） |
| `revocation_failed` | 撤销签名/持久化失败，撤销与审计链整体回滚（500，可安全重试） |

## 验收回执（可离线核验）

`/verify` 每一次正式验收（`accepted`）都会签发一份**验收回执**：服务将

- 验签输入的**确定性摘要** `input_digest`（规范化请求信封的 canonical JSON 之 SHA-256，`sha256:<base64>`；头字段顺序参与计算）；
- 签名者 `keyid` 与**密钥版本**、验收所用**策略版本**、算法、标签、nonce；
- **验收时间**（unix 秒）与**唯一回执 ID**（UUID）；

组成**版本化规范载荷**（`receipt/v1`，行式规范文本），用**服务端 Ed25519 回执签名密钥**签名，并与 nonce 占用（如存在）在**同一数据库事务**中持久化。签发或持久化失败时整个事务回滚（nonce 不被消费，客户端可安全重试）；**拒绝、重放与 `/verify-shadow` 一律不产生回执**；并发重复 nonce 至多生成一份回执。

规范载荷示例（`payload` 字段的原始文本，签名对象即这段字节）：

```
receipt/v1
receipt_id: d56b60a2-078c-4443-8863-8ad2f05643db
key_id: receipt-signing#1
issued_at: 1790301296
keyid: key-1
key_version: 3
policy_version: 1
algorithm: ed25519
label: sig1
nonce: dkHMsQDdYntJZCnnYFffog
input_digest: sha256:0iuiS2Ns+4A7JoMwkHv5oGL4HjRCWSwyNdXWjg4J7Is=
```

### 回执相关接口

| 接口 | 说明 |
| --- | --- |
| `GET /receipts/{receipt_id}` | 按唯一 ID 查询回执（公开，无需令牌）；不存在返回 `404 receipt_unknown` |
| `GET /receipts/{receipt_id}/status?at=<unix>` | **按时点**查询回执状态：`valid` / `revoked` / `unknown`（公开）；内嵌回执与签名撤销证明 |
| `GET /receipts/keys` | **公开**全部历史回执验签公钥（含已轮换的 `retired` 版本、`fingerprint`、起止时间；永不包含私钥） |
| `POST /admin/receipt-keys/rotate` | （管理接口）原子轮换回执签名密钥：旧版本退役、新版本生效；旧公钥继续公布，**旧回执/旧撤销在轮换后仍可离线核验** |
| `POST /admin/receipts/{id}/revoke` | （管理接口）事务内幂等撤销回执（`reason` / `effective_at` / `expected_revision`），返回不可变签名撤销记录 |
| `GET /admin/audit/events` | （管理接口）列出哈希链式审计事件并返回链完整性校验结果 |

```bash
curl -s http://localhost:8000/receipts/keys | jq .
curl -s http://localhost:8000/receipts/d56b60a2-078c-4443-8863-8ad2f05643db | jq .
curl -s "http://localhost:8000/receipts/d56b60a2-078c-4443-8863-8ad2f05643db/status" | jq .
curl -sX POST http://localhost:8000/admin/receipt-keys/rotate -H "X-Admin-Token: admin-secret" | jq .
curl -sX POST http://localhost:8000/admin/receipts/d56b60a2-078c-4443-8863-8ad2f05643db/revoke \
  -H "X-Admin-Token: admin-secret" -H 'Content-Type: application/json' \
  -d '{"reason":"key compromise","effective_at":1790301400,"expected_revision":0}' | jq .
curl -s http://localhost:8000/admin/audit/events -H "X-Admin-Token: admin-secret" | jq .
```

### 离线验签

回执核验完全离线进行，无需访问服务或数据库。仓库提供可独立运行的验签器 `tools/verify_receipt.py`（仅依赖 `cryptography` 与仓库内的 `app.receipts` / `app.crypto`）：

```bash
pip install cryptography

# 1. 保存回执（/verify 响应中的 .receipt，或 GET /receipts/{id} 的响应）
curl -s http://localhost:8000/receipts/<receipt_id> > receipt.json
# 2. 保存公开验签公钥（轮换后旧公钥仍在其中）
curl -s http://localhost:8000/receipts/keys > keys.json
# 3. 离线核验：规范载荷结构 → 镜像字段一致 → Ed25519 签名
python3 tools/verify_receipt.py --receipt receipt.json --keys keys.json
# 4. 可选：校验回执与某次 /verify 请求体的绑定（重算确定性摘要）
python3 tools/verify_receipt.py --receipt receipt.json --keys keys.json --request request.json
```

全部通过时退出码为 0 并打印 `OK: receipt <id> verified offline`；任一检查失败退出码为 1。`--receipt` 也接受完整的 `/verify` 响应 JSON（自动提取其中的 `receipt`）。

## 验收回执撤销与时点核验

管理员可以撤销一份已签发的验收回执。撤销是**幂等命令**，并且与签发一样满足「同事务、可签名、可离线核验、重启与并发结果一致」。

### 撤销命令（管理接口，事务内幂等）

`POST /admin/receipts/{receipt_id}/revoke`（需要 `X-Admin-Token`）

```json
{
  "reason": "签名私钥疑似泄露",
  "effective_at": 1790301400,
  "expected_revision": 0
}
```

| 字段 | 说明 |
| --- | --- |
| `reason` | 撤销原因，非空、单行（不允许换行），最长 1024 字符；会被签入不可变记录 |
| `effective_at` | 撤销生效时刻（unix 秒）；**不得早于回执签发时刻**（拒绝任何「时间倒流」） |
| `expected_revision` | 乐观并发基线：管理员看到的回执修订号；未撤销回执的当前修订号为 **0** |

服务端在**一个事务**内完成：

1. 取全局审计链 advisory lock，再 `SELECT ... FOR UPDATE` **锁定该回执行**；
2. 回执不存在 → `404 receipt_unknown`；
3. 已存在撤销记录：
   - 命令内容相同（`reason` + `effective_at` 一致）→ **幂等重放**，返回 `200` 与**同一份不可变证明**（`idempotent: true`，即使 `expected_revision` 是旧值也不报错）；
   - 命令内容不同 → `409 receipt_already_revoked`（携带既有 `revocation_id` 与 `current_revision`）；
4. 新撤销若 `expected_revision != 0` → `409 revocation_revision_conflict`（携带 expected/current）；
5. `effective_at < 回执 issued_at` → `409 revocation_effective_before_issuance`；
6. 生成不可变、带序号的撤销记录并以**当前服务端 Ed25519 回执签名密钥**签名，同时向哈希链式审计表追加一条记录，两者**原子提交**（任一失败整事务回滚，回执仍保持 `valid`）。

首次撤销返回 `201`：

```bash
curl -sX POST http://localhost:8000/admin/receipts/<receipt_id>/revoke \
  -H "X-Admin-Token: admin-secret" -H 'Content-Type: application/json' \
  -d '{"reason":"key compromise","effective_at":1790301400,"expected_revision":0}'
```

```json
{
  "revoked": true,
  "idempotent": false,
  "current_revision": 1,
  "revocation": {
    "revocation_id": "8f1c…-uuid",
    "key_id": "receipt-signing#1",
    "receipt_id": "d56b60a2-078c-4443-8863-8ad2f05643db",
    "sequence": 1,
    "revision": 1,
    "receipt_payload_sha256": "dde7138e1cad…",
    "reason": "key compromise",
    "effective_at": 1790301400,
    "revoked_at": 1790301395,
    "payload": "receipt-revocation/v1\nrevocation_id: …\nkey_id: …\nreceipt_id: …\nsequence: 1\nrevision: 1\nreceipt_payload_sha256: …\nreason: …\neffective_at: …\nrevoked_at: …",
    "payload_sha256": "…",
    "signature": "Ed25519 base64 …"
  }
}
```

撤销记录的签名对象是其 `payload` 字段的原始字节（首行 `receipt-revocation/v1`，字段顺序固定并严格校验）。其中 `receipt_id` + `receipt_payload_sha256`（被撤回执 `payload` 的 SHA-256）把证明**钉死在唯一一份回执上**，`sequence` 是审计链全局无空洞序号，`revision` 是该回执的修订号（撤销后为 1）。

> 并发保证：对同一回执并发提交的多个**不同**命令恰有一个 `201`，其余全部 `409`；并发提交**相同**命令恰有一个 `201`、其余 `200` 幂等返回同一份证明；数据库中至多一条撤销记录、一条审计记录（见 `tests/test_revocations.py`）。所有状态只存于 PostgreSQL，进程重启后查询、幂等结果与审计链校验完全一致。

### 按时点查询回执状态（公开）

`GET /receipts/{receipt_id}/status?at=<unix-seconds>`

`at` 省略时取服务端当前时间。返回该时点的状态与完整的签名证据，便于一次性保存后离线核验：

- **`valid`（有效）**：回执存在且在该时点尚无生效撤销。若撤销已登记但 `effective_at` 在未来，该时点之前仍为 `valid`（响应仍内嵌撤销证明供检查）。
- **`revoked`（已撤销）**：存在 `effective_at <= at` 的撤销记录；响应内嵌签名撤销证明。
- **`unknown`（未知）**：没有这份回执（HTTP 仍为 200，`"unknown"` 本身就是可判定的答案）。

```bash
curl -s "http://localhost:8000/receipts/<receipt_id>/status?at=1790301400" | jq '
  {status, at, issued_at_unix, receipt: .receipt.receipt_id, revocation: .revocation.revocation_id}'
```

```json
{
  "receipt_id": "d56b60a2-078c-4443-8863-8ad2f05643db",
  "status": "revoked",
  "at": 1790301400,
  "issued_at_unix": 1790301296,
  "receipt": { "receipt_id": "…", "payload": "…", "signature": "…", "...": "完整验收回执" },
  "revocation": { "revocation_id": "…", "payload": "…", "signature": "…", "...": "完整撤销证明" }
}
```

### 审计链

`GET /admin/audit/events`（管理接口）按序号返回全部状态变更事件（当前为 `receipt_revoked`），并同时返回链完整性校验结果 `chain: {"ok": true, "entries": N, "first_bad_seq": null}`。

- 审计表 **append-only**：只有 `INSERT`，应用从不 `UPDATE`/`DELETE`；
- 每行的规范文本嵌入上一行 `entry_sha256`（首行前视为 64 个 `0`），校验时**从结构化列重建规范文本**再重算哈希，任何改列、改行、删行都会被发现（`first_bad_seq` 指向第一个断链位置）；
- 撤销记录与其审计事件在**同一事务**提交，签名/持久化失败时两者一起回滚。

### 离线核验撤销（回执 + 历史公钥 + 撤销证明）

`tools/verify_receipt.py` 已扩展，除原有回执检查外，提供撤销证明或时点响应时还会检查：

1. 撤销载荷结构合法（`receipt-revocation/v1`，字段严格定序）且镜像字段一致；
2. 撤销签名能用 `GET /receipts/keys` 公布的**任一服务端公钥**（含已轮换的 `retired` 历史公钥）通过；
3. **跨回执复用必失败**：证明中的 `receipt_id` 与 `receipt_payload_sha256` 必须精确匹配被核回执；
4. **时间倒流必失败**：`effective_at` / `revoked_at` 不得早于回执 `issued_at`；
5. 时点结论一致：给定 `--at`（或状态文档自身的 `at`），`at < effective_at` 必须是 `valid`，`at >= effective_at` 必须是 `revoked`，状态文档自相矛盾（伪造「已撤销」）必失败。

```bash
pip install cryptography

# 保存时点响应（内嵌回执 + 撤销证明）与历史公钥
curl -s "http://localhost:8000/receipts/<receipt_id>/status?at=1790301400" > status.json
curl -s http://localhost:8000/receipts/keys > keys.json

# 离线核验时点状态（也可分开传 --receipt r.json --revocation rev.json）
python3 tools/verify_receipt.py --status status.json --keys keys.json --expect-status revoked
# 撤销生效前的时刻应判定为 valid
python3 tools/verify_receipt.py --status status.json --keys keys.json --at 1790301399 --expect-status valid
```

全部通过退出码 0 并打印 `OK: receipt <id> verified offline (status: revoked|valid)`；任一失败（载荷/镜像被篡改、签名无效、跨回执复用、时间倒流、状态与证明矛盾）退出码 1。

## 示例请求（端到端脚本）

仓库内置一个完整演示客户端：生成 Ed25519 密钥 → 登记公钥 → 对一条带 JSON 正文的请求签名 → 提交验收 → 再次提交展示防重放 → 影子验签 → 用公布的公钥离线核验验收回执 → 撤销第二份回执（含幂等重放、冲突拒绝）→ 按时点查询 valid/revoked/unknown → 离线核验签名撤销证明。

```bash
pip install -r requirements.txt httpx
# 终端 A：docker compose up --build（或指向已运行的实例）
# 终端 B：
PYTHONPATH=. python3 examples/demo_client.py http://localhost:8000 admin-secret
```

预期输出（节选）：

```
first  /verify -> 200      {"status": "accepted", "key_version": 1, "receipt": {...}, ...}
second /verify -> 409      {"status": "replayed", "reason": "replayed", ...}
receipt d56b60a2-... (key receipt-signing#1): signature OK, input binding OK
```

手写 `curl` 可参考 `examples/` 目录中字段结构；签名逻辑（Content-Digest、基串、签名）见 `app/signer.py`，可直接作为 SDK 参考。

## 防重放的原子性保证

- 表 `used_nonces` 上有 `UNIQUE (keyid, nonce)` 约束；
- 验签通过后，插入 nonce、签发并持久化验收回执与提交结果在**同一事务**中完成（`psycopg2` 单连接），重复键冲突即回滚并返回 `replayed`；回执签发/持久化失败同样整体回滚；
- 已用并发压测验证：20 个完全相同的并发请求恰有 **1 个 accepted、19 个 409 replayed**，且至多生成 **1 份回执**（见 `tests/test_api.py::test_concurrent_replays_only_one_accepted` 与 `tests/test_receipts.py::test_concurrent_duplicate_nonce_yields_single_receipt`）；
- 不同 keyid 使用相同 nonce 互不影响。

### 撤销与审计链的原子性保证

- 表 `receipt_revocations` 对 `receipt_id` 有唯一约束：每份回执至多一条撤销记录；`sequence` 列唯一、对应审计链全局无空洞序号；
- 撤销事务先取审计链全局 advisory lock，再 `SELECT ... FOR UPDATE` 锁定回执行：不同命令并发撤销恰有一个 `201`、其余 `409`，相同命令并发为一个 `201` + 其余幂等 `200`，库中至多一条撤销/审计记录；
- 撤销记录（服务端 Ed25519 签名）与 `audit_events` 哈希链条目在**同一事务**插入，签名或持久化失败整体回滚（回执保持 `valid`、审计链不断）；
- 审计表 append-only、每行嵌入前驱哈希，校验由结构化列重建规范文本，改列/改行/删行均可检出；所有状态只存 PostgreSQL，进程重启后查询、幂等结果、链校验完全一致。

## 本地开发与测试

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
pip install pytest httpx pgserver        # 测试依赖（pgserver 会自动拉起嵌入式 PostgreSQL）

pytest -q                                  # 119 个测试，无需预装 PostgreSQL
```

测试覆盖：RFC 9421 附录 B 基串向量与官方 Ed25519/RSA-PSS 签名、派生组件、SF/遗留头规范化、Content-Digest、密钥轮换、策略、新鲜度、并发防重放、全部稳定原因码，以及策略草稿/原子激活（含并发激活竞争与基线冲突）、影子验签只读性（不消费 nonce、不影响正式验收）、跨版本差异与重启一致性、旧库平滑升级，验收回执（签发与持久化、按 ID 查询、拒绝/重放/影子不产生回执、并发重复 nonce 至多一份、签发失败整体回滚、密钥轮换后旧回执仍可核验、独立离线验签器端到端），以及**回执撤销与时点核验**（事务内幂等撤销、未知/冲突/修订号/时间倒流拒绝、并发下唯一赢家与幂等重放、无空洞全局序号、不可变签名撤销记录、哈希链审计与篡改/删除检出、撤销失败整事务回滚、重启一致性、轮换后历史公钥仍可核验、按时点 valid/revoked/unknown，以及离线工具对篡改、跨回执复用、时间倒流和伪造时点状态的拒绝）。

## 项目结构

```
app/
  config.py      # 环境变量与默认策略
  db.py          # 连接池、建表、密钥版本登记、不可变策略版本/草稿/激活、同事务 nonce 防重放与回执签发、事务内幂等撤销与哈希链审计、按时点状态
  receipts.py    # 回执/撤销版本化规范载荷、验签输入确定性摘要、Ed25519 签名/验签（离线验签器复用）
  policy_diff.py # 策略版本间逐项差异（列表增删 + 标量开关）
  sf9421.py      # 支持字符串标签的 Signature SF 字典解析（基于 http-sfv）
  base.py        # RFC 9421 §2.5 签名基串重建（派生组件/头规范化）
  digest.py      # RFC 9530 Content-Digest 计算与校验
  crypto.py      # Ed25519 / RSA-PSS 公钥载入、验签、签名辅助
  verifier.py    # 端到端验收编排（live 写 nonce + 签回执 / shadow 只读）与稳定原因码
  signer.py      # 客户端签名辅助（演示与测试使用）
  schemas.py     # Pydantic 模型
  main.py        # FastAPI 路由（/verify、/verify-shadow、/receipts/*（含 /status）、/admin/*（含撤销与审计））
tools/
  verify_receipt.py # 可独立运行的离线验签器（回执 + 历史公钥 + 撤销证明 + 时点核验；仅需 cryptography）
examples/
  demo_client.py # 端到端演示脚本（含回执离线核验）
tests/           # pytest 测试套件（含 RFC 官方测试向量与回执测试）
docker-compose.yml
Dockerfile
requirements.txt
```
