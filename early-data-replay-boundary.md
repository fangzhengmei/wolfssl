# TLS 会话票据、恢复握手与早期数据的重放风险责任边界

分析对象：wolfSSL（本仓库 `task/84` 分支）。方法：通读 `src/tls13.c`、`src/internal.c`、`src/ssl_sess.c`、`src/dtls.c` 中票据与 0-RTT 相关实现，以及 `tests/api/test_tls13.c`、`tests/api/test_session.c`、`tests/quic.c`、`scripts/tls13.test` 中的测试材料，划分"库保证的检查"与"应用/共享票据部署必须承担的责任"，并评估握手成功后应用数据重复交付的风险。

## 1. 威胁模型与术语

- **重复票据（duplicate ticket）**：同一 ClientHello（含同一 PSK identity + binder + 0-RTT 记录）被原样重放，或同一票据被客户端合法地用于第二次恢复。
- **过期票据（expired ticket）**：票据年龄超过服务器超时或 RFC 8446 的 7 天上限。
- **不同服务器上下文（different server context）**：票据在与签发者不同的 `WOLFSSL_CTX`、不同进程或不同机器上被解密——包括重启（同密钥）与共享票据密钥的多实例部署两种情形。
- **应用数据重复交付**：同一批 0-RTT 字节被服务器应用层消费两次（同一连接内或跨连接）。

## 2. 库保证的检查（有代码与测试证据）

### 2.1 过期票据：库保证

`DoClientTicketCheck()`（`src/internal.c:46443`）在每次票据恢复时强制执行：

- 票据年龄 > `ssl->timeout`（默认 `WOLFSSL_SESSION_TIMEOUT`=500s，`wolfssl/internal.h:1208`）或 > `TLS13_MAX_TICKET_AGE`（7 天，`internal.h:1448`）→ 拒绝恢复（`WOLFSSL_FATAL_ERROR`，跳过该 PSK）。
- 客户端上报的 ticket age 与服务端计时的一致性检查：容差 ±1000ms，窗口 `MAX_TICKET_AGE_DIFF`=10s（`internal.c:46483-46491`）。这是 RFC 8446 §8.3 时间窗机制的一部分，但 wolfSSL **没有**实现该节另一种"ClientHello 记录（strike register）"机制。
- 版本一致性：`DoClientTicketCheckVersion()`（`internal.c:46383`）拒绝更高版本票据、TLS 1.3 与 ≤1.2 之间的票据混用、超出 `minDowngrade` 的降级。
- 密码套件匹配（`internal.c:46493-46504`）、OpenSSL 兼容模式下的 sessionCtx 匹配（`internal.c:46505-46511`）、SNI/ALPN 绑定哈希（`src/tls13.c:7121-7151`，不匹配的 PSK 被跳过而非致命）。

票据密钥侧：默认加密回调维护两把轮换密钥，`WOLFSSL_TICKET_KEY_LIFETIME`=1 小时（`internal.h:2257`），`TicketEncCbCtx_ChooseKey()`（`internal.c:47538`）只在票据 hint 不超过密钥剩余寿命时用该密钥加密；`DefTicketHintTooLarge()` 过大时干脆不发票据（`tls13.c:15196`）。旧密钥过期后票据无法解密，天然失效。

### 2.2 重复票据 / 0-RTT 单次使用：库保证（单进程、best-effort）

这是 wolfSSL 反重放的核心机制——**以会话缓存驱逐实现票据单次使用**，而非 ClientHello 记录：

- 接受 0-RTT 的全部必要条件（`src/tls13.c:7565-7587`，`CheckPreSharedKeys` 内）：
  1. 客户端发了 `early_data` 扩展且作用在**第一个** PSK 上（`first`）；
  2. 服务器 `maxEarlyDataSz > 0`（默认 0，见 §2.5）；
  3. 票据不早于本 ctx 创建（fresh-start，见 §2.3）；
  4. 票据会话**确实在缓存中命中**（`ssl->options.ticketCacheHit`）；
  5. `wolfSSL_SSL_CTX_remove_session(ssl->ctx, ssl->session) == 1`——即驱逐真实发生才接受。注释明言 "Consuming the cache entry is what bounds the replay … Best effort"（`tls13.c:7582-7584`）。
- 支撑结构：
  - `WOLFSSL_EARLY_DATA` + 票据时强制定义 `WOLFSSL_TICKET_HAVE_ID`（`internal.h:1318-1322`），让无状态自加密票据也携带可索引的会话 ID 进入缓存。
  - `WOLFSSL_EARLY_DATA` + `HAVE_SESSION_TICKET` + `NO_SESSION_CACHE` 直接编译报错，除非显式定义 `WOLFSSL_EARLY_DATA_NO_ANTI_REPLAY` 退出（`tls13.c:116-122`）。
  - 外部缓存（`HAVE_EXT_CACHE` 回调）参与反重放：开启 0-RTT 时查找走 `wolfSSL_GetSessionFromCache`（含外部回调），关闭时只查内部缓存（`internal.c:46603-46627`）；`wolfSSL_SSL_CTX_remove_session` 在内部缓存未命中但注册了 `rem_sess_cb` 时也返回 1 并触发回调（`ssl_sess.c:3695-3701`）。
- 测试证据：
  - `test_tls13_early_data_0rtt_replay`（`tests/api/test_tls13.c:6692`）：有状态票据，第二次恢复时 0-RTT 被拒、握手以 1-RTT 完成，外部缓存 `rem_calls` 恰好为 1。
  - `test_tls13_0rtt_stateless_replay`（`test_tls13.c:6860`）：无状态自加密票据同样单次有效；重发票据只完成 1-RTT。
  - `test_tls13_0rtt_ext_cache_replay` / `test_tls13_0rtt_ext_cache_eviction` / `test_tls13_0rtt_remove_cb_replay`（`test_tls13.c:7019/7111/7159`）：纯外部缓存与"注册 remove 回调不削弱内部缓存"两条路径。
  - `test_wolfSSL_CTX_add_session_ext` case 6（`tests/api/test_session.c:884-893`）：0-RTT 开启时外部缓存被咨询（`get_session_called==1`）。

**边界**：驱逐只覆盖本进程的缓存视图。`ticketCacheHit` 的置位（`DoClientTicketFinalize`，`internal.c:46596-46626`）与 `CheckPreSharedKeys` 中的 `remove_session` 不是一次原子操作——两个并发连接持有同一票据时，两者都可能在对方驱逐前完成查找。代码注释自承 "Best effort"。

### 2.3 不同服务器上下文：部分由库保证

- **不同 ctx / 不同进程（不共享密钥）**：默认票据加密密钥在 ctx 创建时随机生成，其他上下文的票据无法解密，恢复直接失败——库保证。
- **重启（密钥被保留或恢复）**：RFC 8446 §8.2 fresh-start 检查。ctx 创建时记录 `ticketStartTime`（`internal.c:3137-3158`），恢复时若票据的 `ticketSeen` 早于该时间则置 `ticketPredatesCtx`，0-RTT 被拒但恢复握手仍完成（`tls13.c:7179-7216, 7576`）。可用 `wolfSSL_CTX_no_early_data_fresh_start_check()` 显式关闭（`tls13.c:18791`）——API 注释明确要求"仅当反重放状态能可靠跨重启存活时"使用。测试：`test_tls13_0rtt_fresh_start`（`test_tls13.c:7551`，含关闭检查后 0-RTT 被接受的反向断言）。
  -  caveat：`TimeNowInMilliseconds()` 在返回 0（无可靠时钟）时该检查自动禁用（`internal.c:3144-3147`）；在从启动计时的移植平台上"永不在重启前触发"（API 注释，`tls13.c:18783-18785`）；32 位毫秒时钟每 ~49.7 天回绕，回绕带内的歧义按"拒绝 0-RTT"解决（`tls13.c:7184-7211` 长注释）。
- **多实例共享票据密钥的部署**：库**不**提供跨进程/跨机器的反重放。缓存是进程内的；`wolfSSL_CTX_set_tlsext_ticket_keys()` 或自定义 `wolfSSL_CTX_set_TicketEncCb()` 让票据在实例间可解密后，单实例的缓存驱逐对其它实例不可见。这是 §3 的部署责任。

### 2.4 记录层：连接内重放不可能（库保证）

- TLS 1.3：应用数据记录受 AEAD 序号保护，重放记录在解密处失败 → `bad_record_mac` 致命告警（`internal.c:28025-28072`）。握手成功后同一连接内不存在"重复交付应用数据"的路径。
- DTLS 1.3：另有滑动重放窗口（`src/dtls.c` 的 `DtlsUpdateWindow`/`Dtls13UpdateWindowRecordRecvd`），重复数据报在窗口检查处被丢弃；`tests/api/test_dtls13.c:2322`（`test_dtls13_epoch_slot_reuse_replay`）注入重放记录验证。
- 服务器**拒绝**早期数据时：按 RFC 8446 §4.2.10 跳过无法解密的早期数据记录并累计 `earlyDataSz`，超过 `maxEarlyDataSz` 则以 `TOO_MUCH_EARLY_DATA` 致命终止（`internal.c:28035-28065`）；一旦接受了早期数据，解密失败即 `bad_record_mac`，不再跳过。

### 2.5 默认关闭：库保证

`maxEarlyDataSz` 默认为 0：未调用 `wolfSSL_CTX_set_max_early_data()`/`wolfSSL_set_max_early_data()` 的服务器不在 NewSessionTicket 中宣告 0-RTT，客户端持这种票据写早期数据直接失败。测试：`test_tls13_0rtt_default_off`（`test_tls13.c:6805`）。即 0-RTT 是显式 opt-in。

## 3. 应用或共享票据部署必须承担的责任

1. **0-RTT 应用语义的幂等性**。库把重放界定为"每张票据最多接受一次"，但 (a) 它是 best-effort（§2.2 的并发窗口）；(b) 客户端可能在认为上次失败后合法地重发同一请求。RFC 8446 §8.1 要求应用只把幂等操作放进 0-RTT，或自行实现应用层去重（事务 ID、nonce 存储）。库不提供也不检查这一点。
2. **跨实例/跨机器反重放（共享票据部署）**。用 `wolfSSL_CTX_set_tlsext_ticket_keys()` 或自定义 `SessionTicketEncCb` 共享票据密钥后，部署方必须提供共享的"已用票据"状态：注册 `wolfSSL_CTX_sess_set_get_cb/remove_cb` 外部缓存并指向共享存储（库在 0-RTT 开启时会咨询并驱逐外部缓存，§2.2），且 **get-and-evict 的原子性由部署的存储保证**——库的回调序列本身不是分布式的 compare-and-delete。做不到这一点时，共享票据部署中的 0-RTT 等价于无反重放。
3. **自定义票据加密回调的全部密钥管理**。`WOLFSSL_NO_DEF_TICKET_ENC_CB` + `wolfSSL_CTX_set_TicketEncCb()` 下，密钥生成、轮换、key name 索引、过期语义全在应用侧；库只调用回调。
4. **早期数据被拒后的重发**。服务器拒绝 0-RTT 时握手以 1-RTT 完成，库**不**自动把早期数据作为握手后数据重发；客户端应用须用 `wolfSSL_get_early_data_status()`（`WOLFSSL_EARLY_DATA_ACCEPTED/REJECTED/NOT_SENT`，`tls13.c:19040`）判断并重发。若应用不查状态盲目重发，而服务器实际接受了，就会造成**应用层**重复——库两侧都已各自履约，重复纯属应用逻辑。
5. **外部 PSK 的 0-RTT**。非票据 PSK 没有缓存驱逐机制；接受条件退化为"第一个 PSK + `maxEarlyDataSz>0`"。RFC 8446 §8.1 明确外部 PSK 的 0-RTT 无反重放保护，责任全在应用。
6. **编译期退出项的权衡**。`WOLFSSL_EARLY_DATA_NO_ANTI_REPLAY`（`tls13.c:116-122`）和 `wolfSSL_CTX_no_early_data_fresh_start_check()` 都是库提供的显式逃生门；选用即接管对应责任。
7. **时钟**。票据年龄、fresh-start、密钥轮换都依赖 `TimeNowInMilliseconds()`/`LowResTimer()` 的单调与跨重启可比性；移植平台须保证 §2.3 列出的 caveat 不成立，否则应禁用 0-RTT。

## 4. 握手成功后应用数据重复交付的风险评估

| 路径 | 是否可能重复交付 | 依据 |
|---|---|---|
| 同一连接内（TLS） | 否 | AEAD 序号；重放记录 `bad_record_mac` 致命（`internal.c:28068`） |
| 同一连接内（DTLS） | 否 | 重放窗口丢弃；`test_dtls13_epoch_slot_reuse_replay` |
| 跨连接，同一票据重放（单进程，缓存开启） | 被界定为每票据一次 | 缓存驱逐门控（§2.2）；四个重放测试 |
| 跨连接，同一票据并发重放（单进程） | 存在竞态窗口 | 查找与驱逐非原子（§2.2），无并发测试覆盖 |
| 跨连接，共享票据密钥多实例 | 可能 | 无跨进程反重放状态（§3.2） |
| 服务器重启且密钥保留 | 0-RTT 被拒，1-RTT 不受影响 | fresh-start 检查（§2.3），但依赖时钟（§3.7） |
| 客户端应用在拒绝后重发 + 服务器曾接受 | 可能（应用层） | 库不自动重发也不去重（§3.4） |

结论：在默认配置（单进程、缓存开启、0-RTT opt-in）下，库把"握手成功后应用数据重复交付"压缩到两个残余风险——并发驱逐竞态与应用层重发逻辑；两者都不在库的保证范围内。

## 5. 两种配置下的接受条件与证据缺口

### 配置 A：禁用早期数据（`WOLFSSL_EARLY_DATA` 未定义，或 `max_early_data` 保持 0）

**接受条件**：
- 重放风险退化为普通恢复握手：过期票据被 §2.1 拒绝；重复票据只导致多次 1-RTT 恢复，而 1-RTT 数据在握手完成后才交换，受记录层保护，无 0-RTT 式重复交付。
- 票据仍可被重放用于"恢复"本身（会话恢复不是单次的），但这只复用密钥材料，不重复交付应用数据；若部署要求票据单次使用，须自行用外部缓存驱逐（库在 0-RTT 关闭时不咨询外部缓存，`internal.c:46608-46613`）。

**证据**：`test_tls13_0rtt_default_off`（默认不宣告 0-RTT）；`scripts/tls13.test` 的 earlydata 用例（开启时端到端验证）；§2.1/§2.4 全部检查与构建无关（票据年龄、版本、套件、SNI/ALPN 检查在 `WOLFSSL_EARLY_DATA` 之外编译）。

**证据缺口**：
- 无测试断言"0-RTT 关闭时同一票据并发恢复"的行为（预期：都成功，属正常）。
- `TOO_MUCH_EARLY_DATA` 路径（对端强行发送早期数据）有代码无专项单元测试（仅 QUIC 侧 `tests/quic.c:451-473` 覆盖容量上限）。

### 配置 B：允许共享票据（多实例共享票据密钥 + 0-RTT 开启）

**接受条件**（全部满足才认为重放风险受控）：
1. 部署提供共享外部会话存储，并通过 `wolfSSL_CTX_sess_set_new_cb/get_cb/remove_cb` 接入；存储的 get→remove 必须原子（库只保证"回调被调用"，`ssl_sess.c:3695-3701` 甚至在内部未命中时假设外部有该会话）。
2. 每个实例保留 fresh-start 检查（默认开），且各实例时钟同源可比；若用 `wolfSSL_CTX_no_early_data_fresh_start_check()` 关闭，必须由共享存储的持久性替代该保证。
3. 0-RTT 中只放幂等请求，或应用层另有去重（§3.1）。
4. 票据密钥轮换由部署协调（自定义 `TicketEncCb` 时），避免旧密钥长期可解密扩大重放窗口。

**证据**：`test_tls13_0rtt_ext_cache_replay`/`test_tls13_0rtt_ext_cache_eviction` 证明库会咨询并驱逐外部缓存；`test_session.c` case 6 证明 0-RTT 开启时外部缓存参与查找。

**证据缺口**：
- 所有外部缓存测试都是**单进程、单实例、单槽位**模拟；没有任何多 `WOLFSSL_CTX` 共享同一外部存储的并发重放测试，跨实例原子性完全无覆盖。
- 无共享票据密钥（`wolfSSL_CTX_set_tlsext_ticket_keys` 双实例）+ 0-RTT 的端到端重放测试；`test_tls13_0rtt_fresh_start` 只用密钥保留模拟"重启"，不模拟并存的第二个实例。
- 并发竞态（§2.2）无任何测试；`scripts/tls13.test` 的 `early_data_try_max=10` 重试注释（第 38 行）侧面说明早期数据时序存在已知不稳定因素。
- QUIC 0-RTT（`tests/quic.c:1757+`）走同一 `CheckPreSharedKeys` 门控，但无 QUIC 专属的重放测试。

## 6. 证据索引

| 主题 | 代码 | 测试 |
|---|---|---|
| 0-RTT 接受条件 | `src/tls13.c:7558-7607` | `test_tls13.c:6692, 6860, 7111, 7159` |
| 缓存驱逐语义 | `src/ssl_sess.c:3631-3704`、`src/internal.c:46596-46627` | `test_tls13.c:6943, 7019`；`test_session.c:884-893` |
| 票据年龄/过期 | `src/internal.c:46443-46516` | （经恢复类测试间接覆盖） |
| fresh-start | `src/tls13.c:7179-7216, 18779-18803`、`src/internal.c:3137-3158` | `test_tls13.c:7551, 7646` |
| 默认关闭 | `src/internal.c`（ctx 初始化）、`tls13.c:18805+` | `test_tls13.c:6805` |
| 拒绝后跳过记录 | `src/internal.c:28035-28065` | `tests/quic.c:451-473`（容量） |
| 编译期强制 | `src/tls13.c:116-122`、`wolfssl/internal.h:1318-1322` | — |
| 密钥轮换 | `src/internal.c:47538-47600`、`internal.h:2257-2261` | — |
| 版本/套件/SNI/ALPN 绑定 | `src/internal.c:46383-46439`、`src/tls13.c:7121-7151` | 恢复与 SNI/ALPN 测试间接覆盖 |
