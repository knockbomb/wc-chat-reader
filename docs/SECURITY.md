# 安全审计与自检报告

本文档记录本项目的安全设计原则、已识别的风险与缓解措施。

## 设计原则

### 1. 最小权限（Least Privilege）

- **内存扫描器**：仅使用 `PROCESS_VM_READ | PROCESS_QUERY_INFORMATION` 打开目标进程 —— 严格只读，不能修改、注入或调试微信进程。
  - 参见：[`memory_scanner.py:79-95`](../src/wc_chat_reader/key/memory_scanner.py)
- **数据库连接**：使用 `sqlite3` 的 URI 只读模式（`?mode=ro&immutable=1`），即使代码里有 bug 试图 UPDATE/DELETE，SQLite 也会拒绝。
  - 参见：[`db/session.py`](../src/wc_chat_reader/db/session.py)

### 2. 默认拒绝网络暴露（Fail-Closed on Network Binding）

- HTTP 服务默认绑定 `127.0.0.1`，且启动时 [`_assert_local_bind`](../src/wc_chat_reader/api/main.py) 会拒绝非环回地址。要暴露到局域网必须显式在配置中设置 `bind_local_only=false`。
- **原因**：聊天记录属于极敏感数据，任何意外的公网暴露都是灾难。

### 3. 可选的 Bearer 认证

- 通过 `WCR_API_TOKEN=xxx` 或 `Settings(api_token="xxx")` 启用 HTTP + MCP 端点的 Bearer 认证。
- 参见：[`api/deps.py:require_auth`](../src/wc_chat_reader/api/deps.py)

### 4. 数据不落敏感盘

- `.gitignore` 已排除 `wechat_data/`、`output/`、`*.db`、`*.sqlite*`
- 解密输出默认写到 `WCR_WORK_DIR/decrypted/`，非当前工作目录
- 日志默认不含消息内容；即使 DEBUG 级别，输出也仅限元数据（PID、页数、时间戳）

## 已识别风险

### R1: 密钥泄漏到日志

**风险**：如果 CLI 输出被重定向到文件，密钥会永久存到磁盘。

**缓解**：
- `wcreader key` 只在 stdout 打印密钥，从不写文件
- 日志（stderr）里所有密钥用 `hex()[:8]` 缩略
- 用户如果 pipe/tee 输出，责任在用户

### R2: 进程句柄未关闭导致资源泄漏

**缓解**：`WindowsMemoryScanner` 实现了上下文管理器协议（`__enter__` / `__exit__`），`open_scanner()` 强制以 `with` 语句使用。

参见：[`memory_scanner.py`](../src/wc_chat_reader/key/memory_scanner.py)

### R3: Frida 依赖可能带来供应链风险

**缓解**：
- Frida 是 **可选依赖**（`extras = frida`），默认不安装
- 只在内存扫描全部失败后才尝试
- 用户可以完全关闭：`pipeline.extractors = [e for e in pipeline.extractors if e.name != "frida-sqlite3_key"]`

### R4: SQL 注入

**缓解**：
- 所有 SQL 使用参数化占位符（`?`）
- 表名从 `sqlite_master` 白名单获取，不接受用户输入
- 参见：[`repository.py:_read_messages`](../src/wc_chat_reader/db/repository.py)
- 静态检查：`ruff` 启用 `S608`（SQL 注入检测），代码中的 f-string SQL 已用 `# noqa: S608` 明确标注且经过审计

### R5: 路径遍历（Path Traversal）

**缓解**：
- 所有输入路径经过 `Path().resolve()` 规范化
- 媒体文件访问基于白名单目录（`data_dir` 内的相对路径）

### R6: CORS / CSRF

**当前状态**：HTTP 服务默认没启用 CORS，浏览器无法跨源访问，这是刻意为之。
**风险**：如果用户在浏览器里访问某个恶意页面，理论上可以通过 XHR 攻击 localhost:5030。
**缓解**：
- 默认只监听环回地址
- 提供 Bearer token 作为纵深防御
- 未来可加入 `Origin` 头白名单

### R7: 微信进程状态被工具影响

**风险**：如果我们的工具触发微信崩溃，用户可能丢失聊天数据。

**缓解**：
- 只读打开，永不写入
- 使用 `MEM_COMMIT | MEM_PRIVATE` 过滤器避免读取内核区
- 所有 `ReadProcessMemory` 调用检查返回值，失败即跳过

## 静态检查基线

```bash
ruff check src tests        # 语法风格 + 安全 (S 系列规则)
mypy src                    # 严格类型检查
pytest --cov                # 单元 + 集成测试，含覆盖率报告
```

## 依赖安全审查

关键依赖及其角色：

| 包 | 用途 | 信任来源 |
|---|---|---|
| pycryptodome | AES / PBKDF2 / HMAC | 密码学社区维护，PyPI 顶级下载 |
| fastapi | HTTP 层 | Sebastián Ramírez + 大量企业采用 |
| pydantic | 数据验证 | 同上 |
| psutil | 进程枚举 | 老牌跨平台库 |
| pywin32 | Windows API 绑定 | Microsoft 官方推荐 |
| frida (可选) | 动态插桩 | ole.andre.ravnas 主导 |

建议使用 `pip-audit` 或 `safety` 定期扫描：

```bash
pip install pip-audit
pip-audit
```

## 合规声明

- 本项目不含任何微信官方代码
- 所有加密算法参数（PBKDF2 迭代次数、HMAC 算法）来自 SQLCipher 公开文档
- 内存扫描模式（pattern bytes）基于 [已删除的 sjzar/chatlog](https://github.com/LOVECHEN/sjzar-chatlog) 的开源代码逆向研究成果
- 使用者必须遵守当地法律，参见 [DISCLAIMER.md](../DISCLAIMER.md)
