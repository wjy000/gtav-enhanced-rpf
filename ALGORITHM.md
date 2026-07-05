# GTA V Enhanced RPF7 解包算法详解

本文档记录 `rpf-enhanced` 项目中所有加密 / 解密算法的实现细节。所有算法均严格基于公开的开源代码移植，**不含任何自创或猜测的步骤**。每节都标注了参考来源与对应的源码位置，便于后续审计与对照。

> 目标：让任何具备基础密码学知识的开发者读完本文后，能独立在任意语言中复现 Enhanced RPF7 的解包过程。

---

## 目录

1. [总体流程](#1-总体流程)
2. [Enhanced 与 Legacy 的差异](#2-enhanced-与-legacy-的差异)
3. [PC_AES_KEY 提取（SHA1 扫描）](#3-pc_aes_key-提取sha1-扫描)
4. [Jenkins One-At-A-Time Hash](#4-jenkins-one-at-a-time-hash)
5. [.NET System.Random 兼容实现](#5-net-systemrandom-兼容实现)
6. [magic.dat 解密](#6-magicdat-解密)
7. [AES-256-ECB](#7-aes-256-ecb)
8. [Raw DEFLATE 解压](#8-raw-deflate-解压)
9. [密钥布局切片](#9-密钥布局切片)
10. [RPF7 文件头与 TOC 解析](#10-rpf7-文件头与-toc-解析)
11. [TFIT NG 块密码](#11-tfit-ng-块密码)
12. [资源 / 二进制文件提取](#12-资源--二进制文件提取)
13. [实现踩坑记录](#13-实现踩坑记录)

---

## 1. 总体流程

```
┌─────────────────────┐
│ GTA5_Enhanced.exe   │
│ (≈ 52 MB)           │
└──────────┬──────────┘
           │ ① 扫描 SHA1，找到 32 字节 PC_AES_KEY
           ▼
┌─────────────────────┐    ┌──────────────────┐
│ PC_AES_KEY (32 B)   │◄───│ PC_AES_KEY_HASH  │
└──────────┬──────────┘    │ (公开常量)        │
           │               └──────────────────┘
           │ ② Jenkins hash(aes_key) 作为 PRNG 种子
           ▼
┌─────────────────────┐
│ DotNetRandom        │
│ (Knuth 减法生成器)   │
└──────────┬──────────┘
           │ ③ 生成 4 路随机字节流 rb1..rb4
           ▼
┌─────────────────────────────┐
│ magic.dat (154069 B, 公开)  │
│ db[i] = m[i] - rb1..4[i]   │  ④ 减随机流
└──────────┬──────────────────┘
           │ ⑤ AES-256-ECB 解密
           ▼
       ┌───────┐
       │ raw   │  ⑥ Raw DEFLATE 解压
       │ DEFL  │
       └───┬───┘
           │ ⑦ 切片
           ▼
┌─────────────────────────────────────┐
│ [27472] NG keys  (101 × 272 B)      │
│ [278528] NG tables (17×16×256 u32)  │
│ [256]    LUT                        │
│ [16]     AWC key                    │
└─────────────────────────────────────┘
           │
           │ ⑧ 用 NG keys + tables 解密 RPF7 TOC
           ▼
       文件名 + 元数据
           │
           │ ⑨ 按 entry 偏移读取并解密文件体
           ▼
       原始文件数据
```

---

## 2. Enhanced 与 Legacy 的差异

CodeWalker 在 commit [`2facae37`](https://github.com/dexyfex/CodeWalker/commit/2facae37dd52a7e87314bfa4cecf7f4b36488f84)（2025-03-11）合并了对 Enhanced 的支持。完整 diff 显示**唯一改动**只是 exe 文件名：

```diff
- byte[] exedata = File.ReadAllBytes(path + "\\gta5.exe");
+ var exefile = gen9 ? "\\gta5_enhanced.exe" : "\\gta5.exe";
+ byte[] exedata = File.ReadAllBytes(path + exefile);
```

| 项目 | Legacy | Enhanced |
|---|---|---|
| RPF 格式 | RPF7 (`7FPR`) | RPF7 (`7FPR`) — **不变** |
| 加密标签 (`Encryption`) | `0xFEFFFFF` (NG/TFIT) | `0xFEFFFFF` (NG/TFIT) — **不变** |
| `PC_AES_KEY` | 在 exe 中（每个 exe 独有） | 在 exe 中（**与 Legacy 不同**，需各自提取） |
| `magic.dat` | 公开加密包 | **完全相同** |
| NG keys / tables / LUT / AWC | 由 magic.dat 解出 | **完全相同** |

**结论**：Enhanced 唯一独有的是 `PC_AES_KEY`，从 `GTA5.exe`（Enhanced 版 ~52 MB）中按 SHA1 扫描得到。`magic.dat` 与所有衍生密钥都是公开常量。

Gen9 判定（CodeWalker `GTAFolder.IsGen9Folder`）：

```csharp
return File.Exists(folder + @"\gta5_enhanced.exe");
```

仅检查游戏目录下是否存在 `gta5_enhanced.exe`。

---

## 3. PC_AES_KEY 提取（SHA1 扫描）

**来源**：`CodeWalker.Core/GameFiles/Utils/GTAKeys.cs` → `GenerateV2`

```csharp
public static void GenerateV2(byte[] exeData, Action<string> updateStatus)
{
    var exeStr = new MemoryStream(exeData);
    PC_AES_KEY = HashSearch.SearchHash(exeStr, GTA5KeyHashes.PC_AES_KEY_HASH, 0x20);
}
```

**算法**：在 exe 字节流中滑动一个 32 字节窗口（`0x20`），计算每个窗口的 SHA1，与公开常量 `PC_AES_KEY_HASH` 比对。首个匹配即 `PC_AES_KEY`。

```python
PC_AES_KEY_HASH = bytes([
    0xA0, 0x79, 0x61, 0x28, 0xA7, 0x75, 0x72, 0x0A,
    0xC2, 0x04, 0xD9, 0x81, 0x9F, 0x68, 0xC1, 0x72,
    0xE3, 0x95, 0x2C, 0x6D,
])

def find_aes_key(exe_data: bytes) -> bytes:
    for i in range(len(exe_data) - 31):
        candidate = exe_data[i:i + 32]
        if hashlib.sha1(candidate).digest() == PC_AES_KEY_HASH:
            return candidate
    raise ValueError("AES key not found")
```

**实测结果**（`/Volumes/Grand Theft Auto V Enhanced/GTA5.exe`，55203448 字节）：
```
PC_AES_KEY = b38973af8b9e263a8df170321442b3938bd3f21fa4d04dff882e04660ff99dfd
SHA1        = a0796128a775720ac204d9819f68c172e3952c6d   ✓ 匹配 PC_AES_KEY_HASH
```

> Enhanced 与 Legacy **共用同一个 `PC_AES_KEY_HASH`**，但 exe 中匹配到的实际字节不同。

---

## 4. Jenkins One-At-A-Time Hash

**来源**：`CodeWalker.Core/GameFiles/Utils/Jenk.cs` → `GenHash(byte[])`

```csharp
public static uint GenHash(byte[] data)
{
    uint h = 0;
    for (uint i = 0; i < data.Length; i++)
    {
        h += data[i];
        h += (h << 10);
        h ^= (h >> 6);
    }
    h += (h << 3);
    h ^= (h >> 11);
    h += (h << 15);
    return h;
}
```

**Python 实现**（注意 Python int 不会溢出，需显式 `& 0xFFFFFFFF`）：

```python
_MASK = 0xFFFFFFFF

def jenkins_hash(data: bytes) -> int:
    h = 0
    for b in data:
        h = (h + b) & _MASK
        h = (h + ((h << 10) & _MASK)) & _MASK
        h ^= h >> 6
    h = (h + ((h << 3) & _MASK)) & _MASK
    h ^= h >> 11
    h = (h + ((h << 15) & _MASK)) & _MASK
    return h
```

**关键点**：
- 输入是 `PC_AES_KEY` 的**原始字节**（不是字符串，不做大小写转换、不做 UTF-8 编码）。
- 全程 32 位无符号算术。
- `>> 6`、`>> 11` 是逻辑右移（uint 语义）。

**实测**：`jenkins_hash(PC_AES_KEY) = 0x95996749`（无符号 2508415817）。

---

## 5. .NET System.Random 兼容实现

**来源**：[Microsoft Reference Source — mscorlib/system/random.cs](https://github.com/microsoft/referencesource/blob/master/mscorlib/system/random.cs)

CodeWalker 用 `new Random((int)JenkHash.GenHash(PC_AES_KEY)).NextBytes(buf)` 生成随机字节流。Python 必须逐行复刻 .NET Framework 的 `Random`，否则字节流会偏离。

### 5.1 常量与状态

```csharp
private const int MBIG =  Int32.MaxValue;    // 0x7FFFFFFF
private const int MSEED = 161803398;
private int inext;
private int inextp;
private int[] SeedArray = new int[56];
```

### 5.2 构造函数（Knuth 减法生成器）

```csharp
public Random(int Seed) {
    int ii;
    int mj, mk;
    int subtraction = (Seed == Int32.MinValue) ? Int32.MaxValue : Math.Abs(Seed);
    mj = MSEED - subtraction;
    SeedArray[55] = mj;
    mk = 1;
    for (int i = 1; i < 55; i++) {        // 注意 i 从 1 到 54
        ii = (21 * i) % 55;
        SeedArray[ii] = mk;
        mk = mj - mk;
        if (mk < 0) mk += MBIG;
        mj = SeedArray[ii];
    }
    for (int k = 1; k < 5; k++) {         // 4 次混洗
        for (int i = 1; i < 56; i++) {    // i 从 1 到 55
            SeedArray[i] -= SeedArray[1 + (i + 30) % 55];
            if (SeedArray[i] < 0) SeedArray[i] += MBIG;
        }
    }
    inext = 0;
    inextp = 21;
}
```

### 5.3 InternalSample 与 NextBytes

```csharp
private int InternalSample() {
    int retVal;
    int locINext = inext;
    int locINextp = inextp;
    if (++locINext >= 56) locINext = 1;
    if (++locINextp >= 56) locINextp = 1;
    retVal = SeedArray[locINext] - SeedArray[locINextp];
    if (retVal == MBIG) retVal--;
    if (retVal < 0) retVal += MBIG;
    SeedArray[locINext] = retVal;
    inext = locINext;
    inextp = locINextp;
    return retVal;
}

public virtual void NextBytes(byte[] buffer) {
    for (int i = 0; i < buffer.Length; i++)
        buffer[i] = (byte)(InternalSample() % (Byte.MaxValue + 1));   // 0..255
}
```

### 5.4 Python 实现要点

Python 的 int 不会溢出，而 C# `int` 运算会回绕到 int32。因此**每次算术运算后必须显式调用 `_i32()` 包装**：

```python
def _i32(x: int) -> int:
    """把 Python int 包装到 C# int 的有符号 32 位范围。"""
    x &= 0xFFFFFFFF
    if x >= 0x80000000:
        x -= 0x100000000
    return x
```

**验证向量**（来自 [.NET 官方文档 Random(Int32)](https://learn.microsoft.com/dotnet/api/system.random.-ctor)）：

| `Seed` | `Next()` 前 6 个值 |
|---|---|
| `123` | `2114319875, 1949518561, 1596751841, 1742987178, 1586516133, 103755708` |
| `456` | `2044805024, 1323311594, 1087799997, 1907260840, 179380355, 120870348` |

`rpf-enhanced` 的 `DotNetRandom` 在这两个 seed 上的输出与上表**逐字节匹配**。

---

## 6. magic.dat 解密

**来源**：`CodeWalker.Core/GameFiles/Utils/GTAKeys.cs` → `UseMagicData`

### 6.1 magic.dat 文件

- 仓库路径：`CodeWalker.Core/Resources/magic.dat`
- raw URL：`https://raw.githubusercontent.com/dexyfex/CodeWalker/master/CodeWalker.Core/Resources/magic.dat`
- 大小：**154069 字节**（= 16 × 9629 + 5，末尾 5 字节未对齐到 AES 块）
- SHA256：`dc35981f822e892ced3aa81d31e7a96927d573ee28f67417592b5afeaf330832`
- 在 CodeWalker 中通过 `Resources.resx` 嵌入到 DLL，引用名 `Resources.magic`
- Enhanced 与 Legacy **使用同一份 magic.dat**

### 6.2 完整步骤

```python
# 步骤 0：种子 = (int)JenkHash.GenHash(PC_AES_KEY)
# C# 的 (int)uint 是按位重新解释为有符号 32 位
seed_unsigned = jenkins_hash(aes_key)          # 例: 0x95996749
seed_signed   = seed_unsigned - 0x100000000 if seed_unsigned >= 0x80000000 else seed_unsigned

rng = DotNetRandom(seed_signed)

# 步骤 1：生成 4 路独立随机字节流（必须按 rb1 → rb2 → rb3 → rb4 顺序）
magic = MAGIC_DAT                              # 154069 字节
n     = len(magic)
rb1 = bytearray(n); rng.next_bytes(rb1)
rb2 = bytearray(n); rng.next_bytes(rb2)
rb3 = bytearray(n); rng.next_bytes(rb3)
rb4 = bytearray(n); rng.next_bytes(rb4)

# 步骤 2：减随机流（加密方向是 + rb1 + rb2 + rb3 + rb4）
db = bytearray(n)
for i in range(n):
    db[i] = (magic[i] - rb1[i] - rb2[i] - rb3[i] - rb4[i]) & 0xFF

# 步骤 3：AES-256-ECB 解密（仅处理 16 字节对齐的前缀；末尾 5 字节原样保留）
aligned = n - (n % 16)
decrypted = AES.decrypt(db[:aligned], aes_key) + db[aligned:]

# 步骤 4：raw DEFLATE 解压
inflated = zlib_decompress_raw(decrypted)      # 输出 306272 字节
```

### 6.3 关键陷阱

1. **4 路 NextBytes 必须顺序调用，不可合并**。.NET Random 的内部状态是顺序推进的，合并会改变字节流。
2. **每个字节是 `0..255` 全字节范围**，不是 `0..127`。来自 `InternalSample() % 256`。
3. **加密方向是 `+`，解密方向是 `-`**。
4. **AES 只解密对齐前缀**，但 DeflateStream 读取的是完整 buffer（含未对齐尾部）。在 Python 中用 `zlib.decompressobj(-15).decompress(buf) + .flush()` 容忍尾部垃圾。
5. **种子转换**：`(int)uint` 在 C# 中是按位 reinterpret，不是截断也不是数学取模。

---

## 7. AES-256-ECB

**来源**：`CodeWalker.Core/GameFiles/Utils/GTACrypto.cs` → `DecryptAESData`

```csharp
var rijndael = Rijndael.Create();
rijndael.KeySize = 256;          // 32 字节 key
rijndael.Key = key;
rijndael.BlockSize = 128;        // 16 字节块
rijndael.Mode = CipherMode.ECB;  // 无 IV
rijndael.Padding = PaddingMode.None;

var buffer = (byte[])data.Clone();
var length = data.Length - data.Length % 16;   // 仅处理对齐前缀
var decryptor = rijndael.CreateDecryptor();
decryptor.TransformBlock(buffer, 0, length, buffer, 0);
return buffer;
```

**Python 实现**（使用 `pycryptodome`）：

```python
from Crypto.Cipher import AES
cipher = AES.new(aes_key, AES.MODE_ECB)
decrypted = cipher.decrypt(data[:aligned]) + data[aligned:]
```

**用途**：
1. 解密 magic.dat（对齐前缀）
2. 解密 RPF7 TOC 与文件数据（当 archive 的 `Encryption == AES` 时）
3. Enhanced 的 RPF7 实际是 NG 加密，所以走第 11 节的 TFIT 路径

---

## 8. Raw DEFLATE 解压

**来源**：`System.IO.Compression.DeflateStream`（.NET 默认 raw DEFLATE，无 zlib 头）

```python
import zlib
decompressor = zlib.decompressobj(-15)         # wbits = -15 表示 raw DEFLATE
inflated = decompressor.decompress(data) + decompressor.flush()
```

**为什么用 `decompressobj` 而不是 `zlib.decompress`**：
`zlib.decompress(data, -15)` 要求流末尾完整，遇到尾部垃圾会抛错。CodeWalker 的 `DeflateStream` 读到自己的流结束符就停，对后续字节无要求 —— 用 `decompressobj` 才能精确复刻这一行为（magic.dat 末尾有 5 字节未对齐残留）。

**预期输出**：`306272` 字节。

---

## 9. 密钥布局切片

**来源**：`CodeWalker GTAKeys.UseMagicData`（行 300-308）

```csharp
byte[] b1 = new byte[27472];    // [0     .. 27472)   NG keys:  101 × 272 B
byte[] b2 = new byte[278528];   // [27472 .. 306000)  tables:   17 × 16 × 256 × 4 B
byte[] b3 = new byte[256];      // [306000.. 306256)  LUT:      256 B
uint[] b4 = new uint[4];        // [306256.. 306272)  AWC key:  16 B
```

| 偏移 | 长度 | 用途 | 解析方式 |
|---|---|---|---|
| `0` | `27472` | 101 个 NG key | 每个 272 字节，连续 |
| `27472` | `278528` | 17 轮 × 16 字节 × 256 项 × u32 (LE) | 见下 |
| `306000` | `256` | LUT（本工具未使用） | — |
| `306256` | `16` | AWC key（本工具未使用） | — |

**tables 解析**：

```python
tables = []
off = 0
for _round in range(17):
    round_t = []
    for _byte_pos in range(16):
        row = []
        for _idx in range(256):
            row.append(int.from_bytes(b2[off:off + 4], "little"))
            off += 4
        round_t.append(row)
    tables.append(round_t)
# 最终形状：tables[round=17][byte_pos=16][byte_value=256] -> u32
```

---

## 10. RPF7 文件头与 TOC 解析

**来源**：`CodeWalker.Core/GameFiles/RpfFile.cs` → `ReadHeader`

### 10.1 文件头（前 16 字节）

```
偏移  长度  字段          说明
0     4    Version       0x52504637 = "RPF7"（小端为 "7FPR"）
4     4    EntryCount    TOC 条目数量
8     4    NamesLength   名字表字节数
12    4    Encryption    加密类型枚举
```

**`Encryption` 枚举**：

| 原始值 | 常量 | 含义 |
|---|---|---|
| `0x04E45504F` | `OPEN` | "OPEN" 字面量，OpenIV 风格无加密 |
| `0x0FFFFFF9` | `AES` | AES-256-ECB |
| `0x0FFFFFFE` | `NG` | TFIT NG（Enhanced 与 Legacy 都用这个） |
| `0x0FFFFFFF` | `DEFAULT` | 等同 NG |

> Enhanced 的 `update2.rpf` 实测 `Encryption = 0xFEFFFFF`（小端显示），对应 NG。

### 10.2 TOC 解密

紧跟文件头的两块数据：

```
偏移 16                长度 EntryCount × 16    entries_data
偏移 16 + EntryCount×16  长度 NamesLength      names_data
```

当 `Encryption == NG` 时，两块分别走 `DecryptNG(data, archive.Name, archive.FileSize)`。`Name` 是 RPF 文件自身名（用于选 NG key），`FileSize` 是整个 RPF 文件的总字节数（作为 length 种子）。

### 10.3 Entry 类型判定

每条 entry 是 16 字节，按第 2 个 u32（偏移 +4 处的 `x`）判定类型：

```python
y, x = struct.unpack_from("<II", entries, base)
if x == 0x7FFFFF00:
    # 目录 entry
elif (x & 0x80000000) == 0:
    # 二进制文件 entry
else:
    # 资源文件 entry（最高位置 1）
```

### 10.4 目录 entry（16 字节）

```
偏移  类型   字段
0     u32   NameOffset      名字在 names_data 中的偏移
4     u32   Ident           固定 0x7FFFFF00
8     u32   EntriesIndex    子条目在 TOC 中的起始索引
12    u32   EntriesCount    子条目数量
```

### 10.5 二进制文件 entry（16 字节）

```
偏移  类型    字段
0     u16    NameOffset
2     u24    FileSize
5     u24    FileOffset             单位：512 字节块
8     u32    FileUncompressedSize
12    u32    EncryptionType         0=未加密, 1=加密
```

字段打包到一个 u64 里：

```python
buf = struct.unpack_from("<Q", entries, base)[0]
name_offset     = buf & 0xFFFF
file_size       = (buf >> 16) & 0xFFFFFF
file_offset     = (buf >> 40) & 0xFFFFFF
uncompressed, enc_type = struct.unpack_from("<II", entries, base + 8)
is_encrypted    = (enc_type == 1)
```

### 10.6 资源文件 entry（16 字节）

```
偏移  类型   字段
0     u16   NameOffset
2     u24   FileSize              若 == 0xFFFFFF 表示 ≥ 0xFFFFFF，真实大小需从数据头读
5     u24   FileOffset            & 0x7FFFFF 取低 23 位（最高位是类型标志）
8     u32   SystemFlags           RSC7 系统页标志
12    u32   GraphicsFlags         RSC7 图形页标志
```

### 10.7 名字读取

`names_data[NameOffset]` 起到下一个 `\x00` 的字节，按 latin-1 解码。

### 10.8 目录树构建

- 第 0 个 entry 必须是目录（root）。
- 用栈遍历：每个目录 entry 的 `[EntriesIndex .. EntriesIndex+EntriesCount)` 区间是其子条目。
- 路径按 `parent_path/name_lower` 拼接（全小写）。

---

## 11. TFIT NG 块密码

**来源**：`CodeWalker.Core/GameFiles/Utils/GTACrypto.cs` → `DecryptNG` / `DecryptNGBlock`
（原始实现来自 Neodymium，MIT 许可）

### 11.1 选 key

```python
def get_ng_key_index(name: str, length: int) -> int:
    h = jenkins_hash(name.lower().encode("utf-8"))
    return (h + length + 101 - 40) % 101
```

- `name`：要解密的数据所属的名字（RPF TOC 用 archive 文件名；文件数据用 entry 名）。
- `length`：数据长度（RPF TOC 用 archive 文件大小；文件数据用 entry.FileSize）。
- 返回 0..100 索引，选 `ng_keys[index]`（272 字节）。

### 11.2 单块（16 字节）解密

每个 272 字节 key 拆成 **17 组 4×u32 subkey**：

```python
key_u32 = [u32_le(key[i*4:i*4+4]) for i in range(68)]   # 272/4 = 68
sub_keys = [
    (key_u32[4*i], key_u32[4*i+1], key_u32[4*i+2], key_u32[4*i+3])
    for i in range(17)
]
```

17 轮结构：

```python
buf = block                                   # 16 字节
buf = round_a(buf, sub_keys[0],  tables[0])
buf = round_a(buf, sub_keys[1],  tables[1])
for k in range(2, 16):                        # round 2..15 用 round_b
    buf = round_b(buf, sub_keys[k], tables[k])
buf = round_a(buf, sub_keys[16], tables[16])  # 最后一轮再用 round_a
```

### 11.3 Round A（字节顺序 0,1,2,3 → 4,5,6,7 → ...）

```python
def round_a(data, key, table):
    x1 = table[0][data[0]]  ^ table[1][data[1]]  ^ table[2][data[2]]  ^ table[3][data[3]]  ^ key[0]
    x2 = table[4][data[4]]  ^ table[5][data[5]]  ^ table[6][data[6]]  ^ table[7][data[7]]  ^ key[1]
    x3 = table[8][data[8]]  ^ table[9][data[9]]  ^ table[10][data[10]]^ table[11][data[11]]^ key[2]
    x4 = table[12][data[12]]^ table[13][data[13]]^ table[14][data[14]]^ table[15][data[15]]^ key[3]
    return pack_le_u32(x1, x2, x3, x4)
```

### 11.4 Round B（字节交叉索引）

```python
def round_b(data, key, table):
    x1 = table[0][data[0]]  ^ table[7][data[7]]  ^ table[10][data[10]] ^ table[13][data[13]] ^ key[0]
    x2 = table[1][data[1]]  ^ table[4][data[4]]  ^ table[11][data[11]] ^ table[14][data[14]] ^ key[1]
    x3 = table[2][data[2]]  ^ table[5][data[5]]  ^ table[8][data[8]]   ^ table[15][data[15]] ^ key[2]
    x4 = table[3][data[3]]  ^ table[6][data[6]]  ^ table[9][data[9]]   ^ table[12][data[12]] ^ key[3]
    return pack_le_u32(x1, x2, x3, x4)
```

### 11.5 块循环

```python
def decrypt_ng(data, keys, name, length):
    key_idx = get_ng_key_index(name, length)
    key = keys.ng_keys[key_idx]
    key_u32 = [...]
    out = bytearray(data)
    for b in range(len(data) // 16):
        out[b*16:(b+1)*16] = decrypt_ng_block(data[b*16:(b+1)*16], key_u32, keys.ng_decrypt_tables)
    return bytes(out)
    # 注意：尾部不足 16 字节的部分原样保留（与 CodeWalker 一致）
```

---

## 12. 资源 / 二进制文件提取

**来源**：`RpfFile.ExtractFileBinary` / `ExtractFileResource`

### 12.1 二进制文件

```python
abs_off = archive.start + entry.file_offset * 512       # 块对齐偏移
size    = entry.file_size or entry.file_uncompressed_size
raw     = data[abs_off : abs_off + size]

if entry.is_encrypted:
    if archive.is_aes:
        raw = aes_ecb_decrypt(raw, keys.aes_key)
    else:                                                  # NG
        raw = decrypt_ng(raw, keys, entry.name, entry.file_uncompressed_size)

if entry.file_size > 0:                                    # FileSize>0 表示 DEFLATE 压缩
    raw = zlib_decompress_raw(raw)
```

### 12.2 资源文件（RSC7）

资源文件的前 0x10 字节是 RSC7 头（含 system/graphics 页标志），跳过；其余部分按上面同样流程解密 + 解压：

```python
HEADER = 0x10
totlen = entry.file_size - HEADER                          # 有效载荷长度
payload = data[abs_off + HEADER : abs_off + HEADER + totlen]

if entry.is_encrypted:
    payload = decrypt_ng(payload, keys, entry.name, entry.file_size)

try:
    payload = zlib_decompress_raw(payload)
except zlib.error:
    pass                                                   # 未压缩则保留原文
```

> `.ysc`（脚本）资源即使 archive 是 NG 也可能是 AES 加密，由 `entry.IsEncrypted` 单独控制。本工具未特殊处理 `.ysc`，统一按 archive 加密模式走。

---

## 13. 实现踩坑记录

开发过程中遇到的非显然问题，按发现顺序记录：

### 13.1 Python int 不会溢出（影响 DotNetRandom）

**症状**：`DotNetRandom(123)` 测试向量完全正确，但 `DotNetRandom(2508415817)`（实际的 AES key jenkins hash）产生**负数**的 `InternalSample` 输出。

**根因**：C# `int` 运算会自动回绕到 int32（[-2³¹, 2³¹)）。Python 的 int 是任意精度，`a - b` 永远是数学结果。在 DotNetRandom 的初始化循环中：

```python
seed_array[i] = seed_array[i] - seed_array[idx]
```

当 `seed_array[i]` 与 `seed_array[idx]` 都是 int32 范围内的值时，Python 计算的差可能超出 int32 范围，但 C# 会回绕。后续的 `if seed_array[i] < 0: seed_array[i] += MBIG` 判断就会与 C# 不一致。

**修复**：每次算术后显式调用 `_i32()`：

```python
seed_array[i] = _i32(seed_array[i] - seed_array[idx])
ret = _i32(seed_array[a] - seed_array[b])
```

### 13.2 magic.dat 长度不是 16 的倍数

**症状**：`AES.decrypt(db)` 抛 `Data must be aligned to block boundary in ECB mode`。

**根因**：magic.dat 长度 154069 = 16×9629 + 5。CodeWalker 的 `DecryptAESData` 只处理对齐前缀，但完整 buffer 仍喂给后续的 `DeflateStream`。

**修复**：

```python
aligned = len(db) - (len(db) % 16)
decrypted = cipher.decrypt(db[:aligned]) + bytes(db[aligned:])
```

### 13.3 zlib.decompress 对尾部垃圾零容忍

**症状**：解密后的对齐前缀用 `zlib.decompress(data, -15)` 报 `incomplete or truncated stream`。

**根因**：CodeWalker 的 `DeflateStream` 读到 DEFLATE 流结束符就停，对后续字节无要求。Python `zlib.decompress(data, -15)` 要求流完整。

**修复**：用 `decompressobj`：

```python
decomp = zlib.decompressobj(-15)
inflated = decomp.decompress(decrypted) + decomp.flush()
```

### 13.4 `(int)uint` 是按位 reinterpret

**症状**：Jenkins hash 为 `0x95996749`（< 0x80000000）时一切正常；但若 hash ≥ 0x80000000，传入 `DotNetRandom` 的种子不对。

**根因**：C# `(int)some_uint` 不是数学取模，而是把 32 位 bit pattern 按补码重新解释为有符号整数。例如 `(int)0xFFFFFFFFu == -1`。

**修复**：

```python
jh_unsigned = jenkins_hash(aes_key)
jh_signed = jh_unsigned - 0x100000000 if jh_unsigned >= 0x80000000 else jh_unsigned
rng = DotNetRandom(jh_signed)
```

`DotNetRandom.__init__` 内部也再次 `_i32(seed)` 兜底。

### 13.5 RPF7 TOC 解密用的 `length` 是整个 archive 文件大小

**症状**：TOC 解密后文件名全是乱码。

**根因**：CodeWalker 调用 `DecryptNG(entries_data, Name, (uint)FileSize)`，这里的 `FileSize` 是**整个 RPF 文件的字节数**（而不是 TOC 数据本身的长度）。这影响 `get_ng_key_index` 的 `length` 参数。

**修复**：在 `Archive.__init__` 中保存 `file_size`，解密 TOC 时传 `self.file_size`：

```python
entries_blob = decrypt_ng(entries_blob, keys, self.name, self.file_size)
```

---

## 参考资料

- **CodeWalker**（主参考）：https://github.com/dexyfex/CodeWalker
  - `CodeWalker.Core/GameFiles/Utils/GTAKeys.cs`
  - `CodeWalker.Core/GameFiles/Utils/GTACrypto.cs`
  - `CodeWalker.Core/GameFiles/Utils/Jenk.cs`
  - `CodeWalker.Core/GameFiles/RpfFile.cs`
  - `CodeWalker.Core/Resources/magic.dat`
  - Enhanced commit: https://github.com/dexyfex/CodeWalker/commit/2facae37dd52a7e87314bfa4cecf7f4b36488f84
- **Microsoft .NET Random 参考源码**：https://github.com/microsoft/referencesource/blob/master/mscorlib/system/random.cs
- **.NET Random 官方文档（含测试向量）**：https://learn.microsoft.com/dotnet/api/system.random.-ctor
- **Swage**（独立 C++ 实现，思路互证）：https://github.com/0x1F9F1/Swage
- **gtamods wiki RPF archive**：https://gtamods.com/wiki/RPF_archive

---

## 许可

本算法实现严格遵循 CodeWalker 与 Neodymium 的 MIT 许可。`magic.dat` 是 CodeWalker 仓库的公开资源，本工具仅作只读使用。
