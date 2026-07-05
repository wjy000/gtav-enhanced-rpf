# rpf-enhanced

> 如需查看英文,请点击 [README.md](README.md)。

一个轻量依赖的 Python 命令行工具,用于读取 **GTA V 增强版**(Gen9,`GTA5_Enhanced.exe`)的 RPF7 归档。专为希望在 macOS / Linux 上获得可脚本化、可替代 CodeWalker 方案的模组开发者打造。

> 本项目与 Rockstar Games 无任何关联。请仅对您合法拥有、合法获取的游戏文件使用。

仅支持 **增强版(Enhanced)** 路径。如需经典版(`GTA5.exe`)支持,请使用
[CodeWalker](https://github.com/dexyfex/CodeWalker) 或
[rpf-cli](https://github.com/VIRUXE/rpf-cli)。

## 状态

已通过真实增强版归档(`update2.rpf`、`common.rpf` 等)验证:

| 命令           | 结果 |
|----------------|------|
| `info`         | 解析头部、加密信息、条目计数 ✓ |
| `list`         | 列出解密后的文件路径,支持 glob 过滤 ✓ |
| `tree`         | 完整目录树 ✓ |
| `extract`      | 写出文件内容正确(已验证 `version.txt` → `1013.34-dev_gen9_sga_live`、`credits.ymt` → 可读文本)✓ |
| `extract-keys` | 写出三个与 CodeWalker 兼容的 `.dat` 文件 ✓ |

## 安装

```sh
git clone <本仓库>
cd rpf-enhanced
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt   # 仅依赖 pycryptodome
```

需要 Python 3.10+(使用了 PEP 604 的 `X | Y` 类型注解语法)。

## 快速开始

```sh
# 1. 提取密钥(仅需一次),会写出 gtav_aes_key.dat + gtav_ng_key.dat + gtav_ng_decrypt_tables.dat
.venv/bin/python -m rpf_enhanced extract-keys \
    --exe "/path/to/GTA5_Enhanced.exe" \
    -o keys/

# 2. 检视归档(每次运行都会重新提取 AES 密钥)
.venv/bin/python -m rpf_enhanced --exe "/path/to/GTA5_Enhanced.exe" info  update2.rpf
.venv/bin/python -m rpf_enhanced --exe "/path/to/GTA5_Enhanced.exe" list  update2.rpf
.venv/bin/python -m rpf_enhanced --exe "/path/to/GTA5_Enhanced.exe" tree  update2.rpf

# 3. 解包全部(或按 glob 过滤)
.venv/bin/python -m rpf_enhanced --exe "/path/to/GTA5_Enhanced.exe" extract update2.rpf -o out/
.venv/bin/python -m rpf_enhanced --exe "/path/to/GTA5_Enhanced.exe" extract update2.rpf '*/version.txt'
```

### 避免每次运行都扫描 52 MB 的 exe

一旦执行过 `extract-keys`,即可复用已保存的 32 字节 AES 密钥——NG 密钥 / 解密表会从 `magic.dat` 在毫秒级重新生成:

```sh
.venv/bin/python -m rpf_enhanced --aes-key keys/gtav_aes_key.dat extract update2.rpf -o out/
```

## 命令

| 子命令         | 说明 |
|----------------|------|
| `info`         | 显示归档元数据(版本、加密方式、条目计数)。 |
| `list [pattern]` | 列出文件路径。可选 glob 通配符,例如 `*.xml`;`-d` 显示详细信息。 |
| `tree [-d N]`  | 目录树。`-d N` 限制深度。 |
| `extract [-o DIR] [pattern]` | 解包文件。`pattern` 按 glob 过滤。 |
| `extract-keys --exe FILE -o DIR` | 从 `GTA5_Enhanced.exe` 提取密钥。 |

## 密钥来源

三个互斥的全局标志用于选择密钥获取方式:

| 标志             | 行为 |
|------------------|------|
| `--exe PATH`     | 对 `GTA5_Enhanced.exe` 做 SHA1 扫描得到 AES 密钥,再从 `magic.dat` 派生 NG 密钥。 |
| `--aes-key FILE` | 读取一个 32 字节的 `gtav_aes_key.dat`,从 `magic.dat` 派生 NG 密钥。 |
| `--keys-dir DIR` | 等同于 `--aes-key DIR/gtav_aes_key.dat`(CodeWalker 风格目录)。 |

## 工作原理

所有加密步骤都**逐行**移植自 CodeWalker 公开的 C# 源码——没有任何逆向或自创算法。
完整流程详见 [`ALGORITHM.md`](ALGORITHM.md)(中文):

1. 扫描 `GTA5_Enhanced.exe`,找到 32 字节窗口,其 SHA1 等于公开常量
   `PC_AES_KEY_HASH`。结果即为用户专属的 AES 密钥。
2. 用 `(int)JenkHash.GenHash(PC_AES_KEY)` 作为种子初始化一个与 .NET 兼容的
   `System.Random`,取出四路字节流 `rb1..rb4`。
3. 对内置的 `magic.dat`(154_069 字节,SHA256
   `dc35981f822e892ced3aa81d31e7a96927d573ee28f67417592b5afeaf330832`)做去混淆:
   `db[i] = (magic[i] - rb1[i] - rb2[i] - rb3[i] - rb4[i]) & 0xFF`。
4. AES-256-ECB 解密,再做原始 DEFLATE 解压 → 306_272 字节,其中包含 101 个 NG 密钥
   + 17×16×256 解密表(+ LUT + AWC 密钥,未使用)。
5. 解析 RPF7 头部,用 TFIT 分组密码解密 NG 加密的文件目录表(TOC),再按 512 字节块偏移读取文件负载。

增强版与经典版内置的 `magic.dat` 完全相同;只有 AES 密钥不同。
已通过 [微软官方 `Random(Int32)` 测试向量](https://learn.microsoft.com/dotnet/api/system.random.-ctor)验证。

## 项目结构

```
rpf-enhanced/
├── README.md
├── ALGORITHM.md              # 完整算法详解(中文)
├── requirements.txt          # pycryptodome
└── rpf_enhanced/
    ├── __main__.py           # 入口:.venv/bin/python -m rpf_enhanced
    ├── cli.py                # argparse 子命令
    ├── dotnet_random.py      # .NET System.Random 移植
    ├── jenkhash.py           # Jenkins one-at-a-time 哈希
    ├── keys.py               # AES 扫描 + magic.dat 去混淆
    ├── crypto.py             # TFIT NG 分组密码
    ├── rpf.py                # RPF7 解析器
    └── magic.dat             # 内置的加密密钥数据块
```

## 致谢

- [CodeWalker](https://github.com/dexyfex/CodeWalker) —— 主要参考实现。
  本仓库中的每个算法都对应 CodeWalker 的 C# 代码:
  - `GTAKeys.GenerateV2` / `UseMagicData` —— 密钥提取
  - `GTACrypto.DecryptNG` / `DecryptNGBlock` —— TFIT 密码(原作者 Neodymium,MIT)
  - `RpfFile.ReadHeader` —— RPF7 布局
  - `Resources/magic.dat` —— 内置密钥数据块
- [Microsoft .NET 参考源码](https://github.com/microsoft/referencesource)
  —— `System.Random`(Knuth 减法生成器)
- [Swage](https://github.com/0x1F9F1/Swage) —— 独立的 C++ 实现,
  用于交叉验证 TFIT 结构
- [gtamods wiki](https://gtamods.com/wiki/RPF_archive) —— RPF 格式参考

## 许可证

MIT,与 CodeWalker 保持一致。详见 `LICENSE`。
