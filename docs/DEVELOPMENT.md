# 开发指南

## 环境搭建

需要 Python 3.10+。

```bash
# 克隆并进入项目
git clone https://github.com/knockbomb/wc-chat-reader.git
cd wc-chat-reader

# 创建虚拟环境
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

# 安装开发依赖
pip install -e '.[dev,frida]'
```

## 代码风格

- **Formatter**：`ruff format`
- **Linter**：`ruff check`（配置见 `pyproject.toml`）
- **Type Checker**：`mypy`（strict 模式）

```bash
ruff check src tests
ruff format src tests
mypy src
```

## 测试

```bash
# 全部测试（含覆盖率）
pytest

# 只跑单元测试（快）
pytest -m unit

# 只跑集成测试
pytest -m integration

# 生成 HTML 覆盖率报告
pytest --cov-report=html && start htmlcov/index.html  # Windows
```

## 项目结构

```
src/wc_chat_reader/
├── core/         # 配置、日志、异常、常量
├── wechat/       # 进程检测
├── key/          # 密钥提取（多策略）
├── decrypt/      # SQLCipher 解密
├── db/           # 查询层 (repository + parsers)
├── api/          # FastAPI HTTP 层
├── mcp/          # MCP SSE 服务器
└── cli/          # Typer CLI
```

## 增加对新微信版本的支持

假设微信 5.0 发布，需要：

### 1. 增加新的密钥提取器

新建 `src/wc_chat_reader/key/v5_extractor.py`：

```python
from wc_chat_reader.core.constants import WeChatVersion
from wc_chat_reader.key._memory_base import _BaseMemoryExtractor, _ExtractParams

class V5MemoryExtractor(_BaseMemoryExtractor):
    name = "v5-memory-scan"
    priority = 5

    _params = _ExtractParams(
        version=WeChatVersion.V5,  # 需要先扩展 WeChatVersion 枚举
        pattern=bytes([...]),       # 通过逆向分析找到新版特征
        ptr_size=8,
    )
```

在 `constants.py` 增加 `V5 = 5`，在 `pipeline.default()` 里注册新提取器即可。

### 2. 增加新的解密器（如果 KDF 参数变了）

多数情况下 SQLCipher 参数不变，只需检查：
- 迭代次数：`SQLCIPHER_V*_ITERATIONS`
- 哈希算法：SHA1 / SHA512 / SHA3?
- HMAC 长度

如需变更，新建 `V5Decryptor`，继承 `SQLCipherDecryptor`。

### 3. 更新 Repository 的表发现

在 `Repository._message_dbs()`、`_contact_dbs()`、`_session_dbs()` 中加入 V5 的路径规则。

### 4. 增加测试

`tests/unit/test_decrypt.py` 里增加 V5 的 fixture 和断言。

## 提交前检查清单

- [ ] `ruff check src tests` 通过
- [ ] `mypy src` 通过
- [ ] `pytest` 全部通过
- [ ] 新增的功能有对应单元测试
- [ ] 涉及安全边界的改动更新了 `docs/SECURITY.md`
- [ ] 涉及架构的改动更新了 `docs/ARCHITECTURE.md`

## Git 提交约定

采用 [Conventional Commits](https://www.conventionalcommits.org/)：

- `feat:` 新功能
- `fix:` 修复
- `docs:` 文档
- `refactor:` 重构（不改变外部行为）
- `test:` 测试
- `chore:` 构建 / 工具

例：

```
feat(key): add V4.1 memory pattern

Support the new memory layout introduced in WeChat 4.1.
The pointer is now offset by 24 bytes from the pattern.
```
