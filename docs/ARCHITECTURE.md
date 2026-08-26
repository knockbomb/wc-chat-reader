# 架构文档

本文档描述 `wc-chat-reader` 的分层架构与设计决策。核心设计原则：**面对微信持续对抗仍保持长期适应性**。

## 层次结构

```
┌────────────────────────────────────────────────────────────┐
│  用户接口层：CLI (Typer) / HTTP (FastAPI) / MCP SSE         │
├────────────────────────────────────────────────────────────┤
│  查询层：Repository — 版本无关的消息 / 联系人 / 群聊查询    │
├────────────────────────────────────────────────────────────┤
│  数据解析层：Parsers — 消息类型 → 结构化字段（文本/图/语音）│
├────────────────────────────────────────────────────────────┤
│  解密层：SQLCipher Decryptor (v3=SHA1, v4=SHA512)          │
├────────────────────────────────────────────────────────────┤
│  密钥提取层：Pipeline (V3/V4 Memory Scanner + Frida)       │
├────────────────────────────────────────────────────────────┤
│  基础层：Process Detector / Config / Logger / Exceptions   │
└────────────────────────────────────────────────────────────┘
```

## 稳定性梯度

不同层受微信版本迭代影响的程度不同：

| 层 | 稳定性 | 说明 |
|---|---|---|
| 用户接口层 | ★★★★★ | 几乎永远不变 |
| 查询层 | ★★★★☆ | 只随数据库 schema 变化 |
| 数据解析层 | ★★★★☆ | 只随消息格式变化 |
| 解密层 | ★★★★☆ | SQLCipher 算法本身极稳定，微信不会轻易更换加密方案 |
| 密钥提取层 | ★★☆☆☆ | **最不稳定**，微信主要在这里迭代对抗 |
| 基础层 | ★★★★★ | 与微信无关 |

**结论**：把所有"微信版本特定"的逻辑集中到密钥提取层，让它成为唯一需要频繁更新的模块。

## 密钥提取的多策略设计

`src/wc_chat_reader/key/pipeline.py` 定义了 `ExtractionPipeline`，按优先级依次尝试多个 `KeyExtractor`：

1. **`V3MemoryExtractor`** (priority=10) — 微信 3.x 内存扫描
2. **`V4MemoryExtractor`** (priority=10) — 微信 4.0 内存扫描
3. **`FridaExtractor`** (priority=50) — Hook `sqlite3_key` 的备用方案

### 为什么这个设计能对抗迭代

- **内存扫描**：一旦微信改变内存布局，只需要修改 `_ExtractParams.pattern` 常量即可（可能是几个字节）
- **Frida 备用**：即使微信完全打乱内存布局，`sqlite3_key(pKey, nKey=32)` 这个 C 函数签名不会变（除非微信换掉整个 SQLCipher）
- **插件式注册**：`pipeline.register(YourExtractor())` 让社区可以贡献新版本的 extractor 而不修改核心代码

## 关键实现路径

### 密钥提取（Windows）

```
CLI: wcreader key
  └▶ find_wechat_processes()               # psutil 遍历进程
      └▶ WindowsMemoryScanner.iter_regions() # ctypes.VirtualQueryEx
          └▶ 在内存中找 pattern
              └▶ ReadProcessMemory(ptr, 32) # 读候选密钥
                  └▶ KeyValidator.validate() # PBKDF2 + AES + HMAC
```

### 解密

```
CLI: wcreader decrypt
  └▶ create_decryptor(version)
      └▶ V3Decryptor / V4Decryptor.decrypt_file()
          └▶ 逐页 PBKDF2 → HMAC 校验 → AES-CBC 解密
              └▶ 输出标准 SQLite 文件
```

### 查询

```
HTTP: GET /api/v1/chatlog?talker=X&time=Y
  └▶ Repository.get_messages()
      └▶ open_readonly(*.db)              # sqlite3 URI 只读模式
          └▶ SELECT + parse_content()
              └▶ 返回 Message pydantic 模型
```

## 数据流

```
WeChat.exe  ─┐
             │
             ▼ (ReadProcessMemory)
      [内存扫描 + Frida]
             │
             ▼ (32-byte AES key)
      [KeyValidator]
             │
             ▼
   Encrypted *.db 文件
             │
             ▼ (PBKDF2 + AES-CBC)
      [SQLCipherDecryptor]
             │
             ▼
   Decrypted *.db 文件
             │
             ▼ (sqlite3, read-only)
      [Repository + Parsers]
             │
             ▼
   Message / Contact / ChatRoom
             │
   ┌─────────┴──────────┐
   ▼                    ▼
 HTTP API           MCP SSE
   │                    │
   ▼                    ▼
  Web/CLI          AI Assistant
```

## 扩展点

想要加入一个新版本的密钥提取器？

```python
from wc_chat_reader.key.base import KeyExtractor, KeyResult
from wc_chat_reader.key.pipeline import ExtractionPipeline

class MyV5Extractor(KeyExtractor):
    name = "v5-memory-scan"
    priority = 5  # 比默认的 v3/v4 更优先

    def supports(self, process): ...
    def extract(self, process, sample_db_path): ...

pipeline = ExtractionPipeline.default()
pipeline.register(MyV5Extractor())
```

想要加入一个新消息类型的解析器？

```python
from wc_chat_reader.db.parsers import register_parser

def parse_new_type(content: str) -> dict:
    return {"kind": "new_type", "text": content}

register_parser(9999, parse_new_type)
```
