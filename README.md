# HTTP 消息签名验收 API

基于 **RFC 9421（HTTP Message Signatures）** 的服务端签名验收服务。管理员登记签名者公钥版本并配置验收策略；客户端提交一条 HTTP 请求的方法、目标 URI、**有序原始头字段**、正文以及 `Signature-Input` / `Signature`，服务将：

1. 按 **RFC 8941 Structured Fields**（`http-sfv`）解析 `Signature-Input` / `Signature`（支持 RFC 9421 的字符串标签 `"sig1"=` 与裸键两种字典键）；
2. 重建派生组件（`@method`、`@target-uri`、`@authority`、`@scheme`、`@path`、`@query`、`@query-param;name=`、`@request-target`）与签名基串（RFC 9421 §2.5），逐字段做遗留（legacy）或 Structured Field 规范化；
3. 校验 **Content-Digest（RFC 9530，sha-256 / sha-512）** 与正文一致；
4. 校验 `created`（未来时钟偏差 `clock_skew`、最长有效期 `max_age`）、`expires`、`nonce`、必签组件、允许的算法等策略；
5. 用登记的公钥验签：**Ed25519**、**RSA-PSS-SHA256**、**RSA-PSS-SHA512**（`cryptography`）；
6. 验签成功后，**在同一数据库事务内**按 `(keyid, nonce)` 原子插入防重放记录，并**签发可离线核验的验收回执**（服务端 Ed25519 密钥签名的版本化规范载荷，与 nonce 占用同事务持久化）：并发重复提交恰有一次 `accepted`、至多一份回执，其余全部 `409 replayed`。

此外，验收策略是**不可变版本化**的：管理员可以当前激活策略为基线创建草稿、做并发安全的原子激活；还提供**影子验签**接口 `/verify-shadow`，按任意历史/草稿策略版本完整执行全部校验，但**绝不写入 `used_nonces`、绝不改变正式验收状态**，并返回相对当前激活版本的逐项差异。

回执生命周期还包括**撤销与时点核验**：管理员可在事务内提交**幂等撤销命令**（按 `receipt_id`，携带原因、`effective_at` 与乐观并发令牌 `expected_revision`），服务锁定回执、拒绝未知或冲突命令，生成**不可变、带全局序号的撤销记录**并以服务端 Ed25519 密钥签名；撤销记录之间以哈希链构成**审计链**，与回执版本号推进在**同一事务**中原子提交，重启与并发下结果一致。任何人都可以按**时点**查询回执状态（`valid` / `revoked` / `unknown`）并获取**签名撤销证明**，离线工具可完整核验回执、历史公钥、撤销证明与审计链（篡改、时间倒流、跨回执复用均会失败）。

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
| `revocation_unknown` | 回执存在但未被撤销，查询其撤销记录时返回（404） |
| `revocation_conflict` | 回执已被**不同**的撤销命令撤销（409，响应携带已生效的撤销记录） |
| `revocation_revision_conflict` | 撤销命令的 `expected_revision` 与回执当前版本不一致（409） |
| `revocation_issuance_failed` | 撤销记录签发或持久化失败，命令整体回滚（500，可安全重试） |

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
| `GET /receipts/keys` | **公开**全部历史回执验签公钥（含已轮换的 `retired` 版本、`fingerprint`、起止时间；永不包含私钥） |
| `POST /admin/receipt-keys/rotate` | （管理接口）原子轮换回执签名密钥：旧版本退役、新版本生效；旧公钥继续公布，**旧回执在轮换后仍可离线核验** |

```bash
curl -s http://localhost:8000/receipts/keys | jq .
curl -s http://localhost:8000/receipts/d56b60a2-078c-4443-8863-8ad2f05643db | jq .
curl -sX POST http://localhost:8000/admin/receipt-keys/rotate -H "X-Admin-Token: admin-secret" | jq .
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

已签发的回执可以被**撤销**（例如签名密钥泄露、验收策略误判）：管理员提交一条**幂等撤销命令**，服务在**单个数据库事务**内完成全部状态迁移，并产出一份**不可变、带全局序号、服务端 Ed25519 签名的撤销记录**；所有撤销记录按序以哈希链连接，构成可离线核验的**审计链**。

### 提交撤销命令

`POST /admin/receipts/{receipt_id}/revoke`（需要 `X-Admin-Token`）

```json
{
  "reason": "signer key compromised",
  "effective_at": 1790301500,
  "expected_revision": 0,
  "command_id": "cmd-2026-09-29-001"
}
```

| 字段 | 说明 |
| --- | --- |
| `reason` | 撤销原因（非空，记入签名载荷） |
| `effective_at` | 撤销生效时刻：unix 秒整数或 ISO-8601 字符串；可早于当前（追溯）或晚于当前（预约） |
| `expected_revision` | 乐观并发令牌，必须等于回执当前版本（未撤销过的回执为 `0`） |
| `command_id` | 可选幂等键；网络重试时携带同一 `command_id` 与相同参数即可安全重发 |

事务内的处理顺序：

1. `SELECT ... FOR UPDATE` **锁定回执行**；`receipt_id` 不存在返回 `404 receipt_unknown`；
2. 若该回执已有撤销记录：**相同命令**（`command_id` 一致且参数一致；未提供 `command_id` 时全部参数一致）返回原记录（`200`，`idempotent_replay: true`），否则返回 `409 revocation_conflict` 并携带已生效的记录；
3. `expected_revision` 与回执当前版本不一致时返回 `409 revocation_revision_conflict`（响应含 `current_revision`）；
4. 在全局 advisory lock 下分配**无间隙全局序号**并读取链头（`UNIQUE(revocation_seq)` 为数据库兜底）；
5. 原子比较并推进回执版本（`revision: 0 → 1`），构造 `revocation/v1` 规范载荷，用当前回执签名密钥签名，插入不可变记录——**撤销记录、回执版本推进与审计链链接在同一事务提交**，任何失败整体回滚（`500 revocation_issuance_failed`，可安全重试）。

成功响应 `201`（重放为 `200`）：

```json
{
  "status": "revoked",
  "receipt_id": "d56b60a2-078c-4443-8863-8ad2f05643db",
  "idempotent_replay": false,
  "revocation": {
    "revocation_id": "9c7d...-...",
    "revocation_seq": 3,
    "receipt_id": "d56b60a2-...",
    "receipt_revision": 1,
    "reason": "signer key compromised",
    "key_id": "receipt-signing#1",
    "command_id": "cmd-2026-09-29-001",
    "effective_at": "2026-09-26T07:58:20+00:00",
    "effective_at_unix": 1790301500,
    "revoked_at": "2026-09-29T12:00:00.123456+00:00",
    "revoked_at_unix": 1790395200,
    "prev_seq": 2,
    "prev_payload_sha256": "9b6c...",
    "payload": "revocation/v1\nrevocation_id: 9c7d...-\nrevocation_seq: 3\n...",
    "payload_sha256": "4f2a...",
    "signature": "k8sQ...base64..."
  }
}
```

规范载荷（签名对象即这段字节，`prev_*` 把每条记录链接到前一条，创世记录两者皆空）：

```
revocation/v1
revocation_id: 9c7da1f0-...
revocation_seq: 3
receipt_id: d56b60a2-078c-4443-8863-8ad2f05643db
receipt_revision: 1
reason: signer key compromised
effective_at: 1790301500
revoked_at: 1790395200
key_id: receipt-signing#1
command_id: cmd-2026-09-29-001
prev_seq: 2
prev_payload_sha256: 9b6c...
```

**保证**：撤销记录**不可变**（数据库触发器拒绝 UPDATE/DELETE）、序号全局无间隙（advisory lock 串行化 + 唯一约束兜底）、每回执至多一条记录（`UNIQUE(receipt_id)`）；全部状态在 PostgreSQL 中，无进程内缓存，**重启与并发下结果一致**（并发相同命令恰有一个 `201`、其余 `200` 重放同一记录；并发不同命令恰有一个成功、其余 `409`）。撤销**不改动**原回执（`GET /receipts/{id}` 响应不变），也不影响 `/verify` 的防重放语义。

### 时点核验与撤销证明查询

| 接口 | 说明 |
| --- | --- |
| `GET /receipts/{receipt_id}/status?at=<unix或ISO-8601>` | **时点状态**（公开）：`valid` / `revoked` / `unknown`；`at` 省略为当前时刻 |
| `GET /receipts/{receipt_id}/revocation` | 回执的签名撤销记录（公开）；未撤销返回 `404 revocation_unknown` |
| `GET /revocations` | 完整**审计链**（公开，按序号升序），响应含 `head_seq` 与 `head_payload_sha256` |

时点状态语义：

- `unknown`：回执不存在，或在 `at` 时刻尚未签发；
- `valid`：回执在 `at` 时刻已签发，且撤销尚未生效（`at < effective_at`，含从未撤销）；
- `revoked`：`at >= effective_at`，响应携带**签名撤销证明**（即撤销记录文档）。

```bash
# 当前状态（含签名撤销证明）
curl -s http://localhost:8000/receipts/<receipt_id>/status | jq .
# 指定时点（unix 秒或 ISO-8601）
curl -s "http://localhost:8000/receipts/<receipt_id>/status?at=1790301500" | jq .
curl -s "http://localhost:8000/receipts/<receipt_id>/status?at=2026-09-26T07:58:20Z" | jq .
# 完整审计链
curl -s http://localhost:8000/revocations | jq .
```

### 离线核验撤销证明与审计链

`tools/verify_receipt.py` 在回执核验之外增加三个可选参数，全程离线：

```bash
# 保存撤销证明（撤销命令响应、GET .../revocation 或 .../status 响应均可）
curl -s http://localhost:8000/receipts/<receipt_id>/revocation > revocation.json
curl -s http://localhost:8000/revocations > chain.json

python3 tools/verify_receipt.py --receipt receipt.json --keys keys.json \
    --revocation revocation.json --at 1790395200 --chain chain.json
```

新增检查（任一失败退出码为 1）：

1. `revocation/v1` 规范载荷结构严格合法，镜像字段与签名载荷一致；
2. 用公布的（含已轮换的）历史公钥验证撤销记录 Ed25519 签名；
3. **跨回执复用必须失败**：撤销证明的 `receipt_id` 必须等于被核验回执；
4. **时间倒流必须失败**：`--at` 必须不早于回执签发时间，且不早于撤销的 `effective_at`；
5. **审计链**：序号从 1 无间隙、每条记录哈希链接前一条、全部签名有效；链文件带有服务端公布的链头（`GET /revocations` 响应）时，链尾必须与链头一致（截断或续接的链被拒绝）；给定 `--revocation` 时必须原样锚定在链中。

## 示例请求（端到端脚本）

仓库内置一个完整演示客户端：生成 Ed25519 密钥 → 登记公钥 → 对一条带 JSON 正文的请求签名 → 提交验收 → 再次提交展示防重放 → 影子验签 → 用公布的公钥离线核验验收回执 → 提交幂等撤销命令 → 时点状态查询 → 离线核验撤销证明与审计链。

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
revoke -> 201
replay -> 200 (idempotent_replay=true)
status at effective_at-10s: valid; at effective_at+10s: revoked
revocation proof: signature OK, receipt binding OK, chain head seq 1
```

手写 `curl` 可参考 `examples/` 目录中字段结构；签名逻辑（Content-Digest、基串、签名）见 `app/signer.py`，可直接作为 SDK 参考。

## 防重放的原子性保证

- 表 `used_nonces` 上有 `UNIQUE (keyid, nonce)` 约束；
- 验签通过后，插入 nonce、签发并持久化验收回执与提交结果在**同一事务**中完成（`psycopg2` 单连接），重复键冲突即回滚并返回 `replayed`；回执签发/持久化失败同样整体回滚；
- 已用并发压测验证：20 个完全相同的并发请求恰有 **1 个 accepted、19 个 409 replayed**，且至多生成 **1 份回执**（见 `tests/test_api.py::test_concurrent_replays_only_one_accepted` 与 `tests/test_receipts.py::test_concurrent_duplicate_nonce_yields_single_receipt`）；
- 不同 keyid 使用相同 nonce 互不影响。

## 本地开发与测试

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
pip install pytest httpx pgserver        # 测试依赖（pgserver 会自动拉起嵌入式 PostgreSQL）

pytest -q                                  # 120 个测试，无需预装 PostgreSQL
```

测试覆盖：RFC 9421 附录 B 基串向量与官方 Ed25519/RSA-PSS 签名、派生组件、SF/遗留头规范化、Content-Digest、密钥轮换、策略、新鲜度、并发防重放、全部稳定原因码，以及策略草稿/原子激活（含并发激活竞争与基线冲突）、影子验签只读性（不消费 nonce、不影响正式验收）、跨版本差异与重启一致性、旧库平滑升级，验收回执（签发与持久化、按 ID 查询、拒绝/重放/影子不产生回执、并发重复 nonce 至多一份、签发失败整体回滚、密钥轮换后旧回执仍可核验、独立离线验签器端到端），以及回执撤销（幂等命令与冲突拒绝、乐观并发版本、并发命令恰一条记录、无间隙哈希审计链、不可变性触发器、签发失败整体回滚、时点状态三态与 `effective_at` 边界、重启一致性、轮换密钥下旧撤销记录可核验、离线工具对篡改/时间倒流/跨回执复用/断链的拒绝）。

## 项目结构

```
app/
  config.py      # 环境变量与默认策略
  db.py          # 连接池、建表、密钥版本登记、不可变策略版本/草稿/激活、同事务 nonce 防重放、回执签发与撤销
  receipts.py    # 回执版本化规范载荷、验签输入确定性摘要、Ed25519 签名/验签（离线验签器复用）
  revocations.py # 撤销记录规范载荷（revocation/v1）与哈希审计链（离线验签器复用）
  policy_diff.py # 策略版本间逐项差异（列表增删 + 标量开关）
  sf9421.py      # 支持字符串标签的 Signature SF 字典解析（基于 http-sfv）
  base.py        # RFC 9421 §2.5 签名基串重建（派生组件/头规范化）
  digest.py      # RFC 9530 Content-Digest 计算与校验
  crypto.py      # Ed25519 / RSA-PSS 公钥载入、验签、签名辅助
  verifier.py    # 端到端验收编排（live 写 nonce + 签回执 / shadow 只读）与稳定原因码
  signer.py      # 客户端签名辅助（演示与测试使用）
  schemas.py     # Pydantic 模型
  main.py        # FastAPI 路由（/verify、/verify-shadow、/receipts/*、/revocations 与 /admin/*）
tools/
  verify_receipt.py # 可独立运行的离线验签器：回执 + 撤销证明 + 审计链（仅需 cryptography）
examples/
  demo_client.py # 端到端演示脚本（含回执离线核验与撤销演示）
tests/           # pytest 测试套件（含 RFC 官方测试向量、回执与撤销测试）
docker-compose.yml
Dockerfile
requirements.txt
```
