# Unicode 双向文本安全审计 API

基于 **FastAPI + SQLite + Docker** 的服务，检测文本中的 Unicode 双向控制字符（Trojan Source / CVE-2021-42574 类攻击面），按 [UAX #9](https://www.unicode.org/reports/tr9/) 的显式嵌入/隔离配对嵌套规则解析，报告每个控制符的码点、逻辑索引、影响范围与未闭合错误，并对危险区段生成**保持逻辑可读顺序**的转义预览。

> 原始文本永远不会被改写：危险区段同时返回 `raw`（原文逐字保留）与 `escaped_preview`（可读转义形式）。

## 检测的字符

| 码点 | 缩写 | 名称 | 配对方式 |
|---|---|---|---|
| U+200E / U+200F / U+061C | LRM / RLM / ALM | 左右/右左/阿拉伯字母标记 | 无配对（info） |
| U+202A / U+202B | LRE / RLE | 左向/右向嵌入 | PDF 弹出 |
| U+202D / U+202E | LRO / **RLO** | 左向/右向**覆盖** | PDF 弹出 |
| U+202C | PDF | 弹出方向格式 | 匹配最近的 LRE/RLE/LRO/RLO |
| U+2066 / U+2067 / U+2068 | LRI / RLI / FSI | 左向/右向/首强字符隔离 | PDI 弹出 |
| U+2069 | PDI | 弹出隔离 | 匹配最近的 LRI/RLI/FSI |
| U+2061–U+2064 | FSA/ITS/ISS/IPF | 隐形数学运算符 | 无配对（info） |

同时在转义预览中暴露零宽空格（U+200B）、BOM/ZWJ 等不可见格式字符。

## 配对与嵌套规则（UAX #9 X1–X9 子集）

1. LRE/RLE/LRO/RLO 入栈，由最近的 PDF 闭合；LRI/RLI/FSI 入栈，由最近的 PDI 闭合。
2. PDF 会跳过尚未终止的隔离层，向下找到属于自己的嵌入层（X7/X9）。
3. PDI 关闭隔离时，隔离内部**未显式闭合的嵌入层会被隐式终止**并报告错误。
4. 只有 PDF/PDI 而无对应开启符 → 孤立闭合符错误。
5. 文本结束时栈中仍有开启符 → 未闭合错误（未闭合的 RLO/LRO 为 **critical**，因为重排效果延伸到文本结尾）。
6. 显式嵌套深度超过上限（125，BD13 相关）→ critical 错误。

## 风险级别

| 级别 | 含义 |
|---|---|
| `info` | 仅有 LRM/RLM/ALM 等标记或无控制符 |
| `low` | 已正确闭合的 LRE/LRI/FSI 等 |
| `medium` | RLE/RLI、未闭合的隔离/嵌入、孤立 PDF/PDI |
| `high` | 存在 RLO/LRO 方向覆盖（无论是否闭合） |
| `critical` | RLO/LRO **未闭合**，或嵌套深度超限 |

记录的整体风险级别取全部控制符中的最高级别。

## 快速开始

### Docker Compose（推荐）

```bash
docker compose up --build
```

服务在 <http://localhost:8000> 启动，交互式文档：<http://localhost:8000/docs>。
SQLite 数据文件保存在命名卷 `bidi-audit-data`（容器内 `/data/audit.db`）。
启动方式无需改动，新增的 `POST /api/v1/audits/diff`、`POST /api/v1/audits/json`、
`POST /api/v1/audits/csv`、`POST /api/v1/audits/gate`、
`POST /api/v1/identifiers/normalization`、
`POST /api/v1/identifiers/normalization/fix-preview`、
`POST /api/v1/identifiers/mixed-script` 与
`POST /api/v1/urls/query-keys`
随服务一起可用（均通过宿主机 8000 端口访问，例如
<http://localhost:8000/api/v1/urls/query-keys>）。

### 仅用 Docker

```bash
docker build -t bidi-audit .
docker run -p 8000:8000 -v "$PWD/data:/data" bidi-audit
```

容器启动时会自动执行 schema 初始化（`python -m app.init_db`）。

### 本地运行（无 Docker）

```bash
pip install -r requirements.txt
./run.sh                     # 初始化 DB 并在 8000 端口启动
# 或：
BIDI_DB_PATH=./data/audit.db python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## API

### `POST /api/v1/audits` — 提交审计

请求体：

```json
{
  "text": "‮malware.exe‬",
  "filename": "patch.diff"
}
```

`filename` 可选；`text` 必填，原样存储不做任何改写。

```bash
curl -s -X POST http://localhost:8000/api/v1/audits \
  -H 'Content-Type: application/json' \
  -d '{"text": "x‮evil.exe‬", "filename": "patch.diff"}' | jq
```

响应（节选）：

```json
{
  "id": 1,
  "risk_level": "high",
  "stored": true,
  "result": {
    "length": 12,
    "max_depth": 1,
    "risk_level": "high",
    "error_count": 0,
    "errors": [],
    "controls": [
      {
        "codepoint": "U+202E",
        "abbreviation": "RLO",
        "name": "RIGHT-TO-LEFT OVERRIDE",
        "kind": "override",
        "logical_index": 1,
        "position": {"line": 1, "column": 2},
        "depth_after": 1,
        "scope_end": 10,
        "paired_with": "U+202C",
        "is_orphan": false,
        "risk": "high"
      }
    ],
    "dangerous_spans": [
      {
        "start": 1,
        "end": 10,
        "reason": "RLO override forces visual reordering of enclosed characters",
        "opener": "RLO",
        "risk": "high",
        "raw": "‮evil.exe",
        "escaped_preview": "⟨RLO⟩evil.exe"
      }
    ],
    "stats": {
      "total_control_chars": 2,
      "by_abbreviation": {"RLO": 1, "PDF": 1},
      "unclosed_openers": 0,
      "orphan_closers": 0,
      "dangerous_span_count": 1
    }
  }
}
```

说明：

- `logical_index` 是 Python/Unicode 码点偏移；`position.line/column` 按换行切分（1 起始）。
- `scope_end` 是配对闭合符的逻辑索引（未闭合时等于文本长度）。
- `escaped_preview` 保持**逻辑顺序**，把控制符渲染为 `⟨RLO⟩` 这类可读占位符，零宽字符渲染为 `⟨U+200B⟩`，换行/Tab 渲染为 `\n` / `\t`。

未闭合 RLO 示例（攻击字符串不以 PDF 结尾，重排延伸至文本末尾）：

```bash
curl -s -X POST http://localhost:8000/api/v1/audits \
  -H 'Content-Type: application/json' \
  -d '{"text": "‮end.js", "filename": "x.js"}' | jq '.result.risk_level, .result.errors'
# "critical"
# ["RLO at logical index 0 (line 1, col 1) is never closed by PDF"]
```

### `POST /api/v1/audits/diff` — 统一 diff 审计

接收一段 **unified diff** 文本（`git diff` / `diff -u` 风格，支持多文件、多 hunk、
重命名、模式变更、二进制补丁以及 `\ No newline at end of file` 标记），**只审计
各 hunk 中以 `+` 开头的新增行**：文件头、删除行（`-`）、上下文行（前导空格）与
No-newline 标记只参与结构解析，不参与分析。

对每个**含新增内容的文件**，按新文件行号顺序重建新增文本并运行 bidi 解析器，再把
命中的**控制符、错误与危险区段**回映射到：

- 新文件路径（`path`，删除文件 `/dev/null` 不产生记录）、新文件的行/列（`position`，
  1 起始，按 hunk 头的 `+起始行,行数` 推进，删除行不推进）；
- 对应 diff 的行/列（`diff_position`，diff 行号 1 起始，列因前导 `+` 整体 +1）；
- 原解析结果中的逻辑索引与数组下标（`logical_index` / `start_logical_index` /
  `end_logical_index` 与 `result_index`），解析结果本身保持不变。

成功后为每个含新增内容的文件**各保存一条审计记录**（`filename` 为新文件路径，
重建的新增文本存入 `raw_text`，映射信息存入记录的 `meta` 字段，可通过
`GET /api/v1/audits/{id}` 取回），返回各记录 ID 与跨文件汇总的最高风险。

```bash
cat > evil.diff <<'PATCH'
diff --git a/src/app.py b/src/app.py
--- a/src/app.py
+++ b/src/app.py
@@ -1,2 +1,3 @@
 import sys
-old = 1
+name = '‮evil.exe‬'
+print(name)
PATCH

curl -s -X POST http://localhost:8000/api/v1/audits/diff \
  -H 'Content-Type: application/json' \
  --data-binary @evil.diff | jq
```

响应（节选）：

```json
{
  "stored": true,
  "file_count": 1,
  "risk_level": "high",
  "items": [
    {
      "id": 13,
      "stored": true,
      "path": "src/app.py",
      "old_path": "src/app.py",
      "text_length": 51,
      "risk_level": "high",
      "max_depth": 1,
      "error_count": 0,
      "control_count": 2,
      "dangerous_span_count": 1,
      "added_line_count": 2,
      "added_lines": [
        {"new_line": 2, "diff_line": 6, "no_newline": false},
        {"new_line": 3, "diff_line": 7, "no_newline": false}
      ],
      "locations": {
        "controls": [
          {
            "result_index": 0,
            "logical_index": 9,
            "path": "src/app.py",
            "position": {"line": 2, "column": 9},
            "diff_position": {"line": 6, "column": 10}
          }
        ],
        "errors": [],
        "dangerous_spans": [
          {
            "result_index": 0,
            "start_logical_index": 9,
            "end_logical_index": 18,
            "path": "src/app.py",
            "position": {"start": {"line": 2, "column": 9},
                         "end": {"line": 2, "column": 18}},
            "diff_position": {"start": {"line": 6, "column": 10},
                              "end": {"line": 6, "column": 19}}
          }
        ]
      },
      "result": { "risk_level": "high", "controls": ["…同 /audits 的原始解析结果…"] }
    }
  ]
}
```

说明：

- `position` 的行是**新文件行号**（跨 hunk 按各 hunk 头推进，不依赖旧文件行号）；
  `diff_position` 行是该字符所在 `+` 行在**整个 diff 文本中的行号**，列含前导 `+`
  的 1 列偏移。`result_index` 可直接索引到 `result.controls[]` / `result.errors[]` /
  `result.dangerous_spans[]` 的对应元素，`logical_index` 与其保持一致。
- `result` 是对**重建后新增文本**（无新增行之间的空行拼接问题：按新文件顺序逐行
  连接，行末按 No-newline 标记决定是否补 `\n`）的原始解析结果，结构与
  `POST /api/v1/audits` 完全一致，因此该记录同样支持 `verify` 与 `sarif`。
- 纯删除文件、二进制补丁（`Binary files … differ` / `GIT binary patch` Base85 段）、
  空文件与无新增行的文件不产生记录（仍计入合法 diff）；所有文件都无新增内容时
  返回 201、`file_count: 0`、`risk_level: "info"`。
- git 的 `a/` `b/` 路径前缀与 C 风格引号路径（如 `"src/a b.txt"`）会被还原。

错误情况：

| 状态码 | 条件 |
|---|---|
| `422` | diff 结构非法（无文件段、hunk 头格式错误、hunk 出现在文件头之外、hunk 体行首字符非法、No-newline 标记位置/文本错误），或 hunk 体行数与头部声明的旧/新行数不一致 |
| `422` | 请求体缺少 `diff` 字段（Pydantic 校验） |

行数不一致时（超出在越界行、截断在 hunk 头）都定位到**首个错误的 diff 行号**：

```json
{
  "detail": {
    "error": "invalid_unified_diff",
    "line": 4,
    "message": "hunk body exceeds the 1 new line(s) declared by its header"
  }
}
```

校验在任何写入之前完成：解析或 hunk 计数失败时**不写入任何记录**（多文件 diff 中
后置文件出错，前面的文件同样不会落库）。

### `POST /api/v1/audits/json` — JSON 文档字符串值审计

接收一段**原始 JSON 文档文本**（`document` 字段），用严格遵循
[RFC 8259](https://datatracker.ietf.org/doc/html/rfc8259) 的解析器递归遍历对象与
数组，对其中每一个**字符串值**运行 bidi 解析（**对象的键只参与解析，绝不审计**），
并为每个字符串值**各保存一条审计记录**。

每个字符串值返回：

- `pointer` — 该值的 [RFC 6901](https://datatracker.ietf.org/doc/html/rfc6901)
  JSON Pointer（键中的 `~` / `/` 转义为 `~0` / `~1`，数组元素用十进制下标；
  文档本身即字符串时为空串 `""`）；
- `span` — 字符串 token 在**原文中的起止偏移**（码点偏移，0 起始、end 排他，
  含两侧引号）；
- `locations` — 每个控制符 / 错误 / 危险区段的**解码位置回映射**：`offset` 为原文
  码点偏移，`position` 为原文的 1 起始行列。`\uXXXX` 转义解码出的控制符定位到
  该转义的反斜杠；UTF-16 代理对（如 `\uD83D\uDE00`）解码为单个字符，定位到首个
  反斜杠；普通转义（`\n`、`\\`、`\/` 等）与键不会被误判为命中。

```bash
curl -s -X POST http://localhost:8000/api/v1/audits/json \
  -H 'Content-Type: application/json' \
  -d '{"document": "{\"name\": \"x\\u202Eevil.exe\\u202C\"}", "filename": "app.json"}' | jq
```

响应（节选）：

```json
{
  "stored": true,
  "value_count": 1,
  "risk_level": "high",
  "items": [
    {
      "id": 21,
      "stored": true,
      "pointer": "/name",
      "span": {"start": 9, "end": 32},
      "text_length": 11,
      "risk_level": "high",
      "control_count": 2,
      "locations": {
        "controls": [
          {"result_index": 0, "logical_index": 1, "pointer": "/name",
           "offset": 11, "position": {"line": 1, "column": 12}}
        ],
        "errors": [],
        "dangerous_spans": [
          {"result_index": 0, "start_logical_index": 1, "end_logical_index": 10,
           "pointer": "/name",
           "offsets": {"start": 11, "end": 25},
           "position": {"start": {"line": 1, "column": 12},
                        "end": {"line": 1, "column": 26}}}
        ]
      },
      "result": { "risk_level": "high", "controls": ["…同 /audits 的原始解析结果…"] }
    }
  ]
}
```

说明：

- 存入审计表的是**解码后的字符串值**（`raw_text`），因此每条记录同样支持
  `verify` 与 `sarif`；记录的 `filename` 为 `<filename>#<pointer>`（未提供
  `filename` 时为 `#<pointer>`），`meta` 中保存 `pointer` / `span` / `locations`。
- 数字、布尔、`null` 不产生记录；文档不含任何字符串值时返回 201、
  `value_count: 0`、`risk_level: "info"`。
- 行列与偏移均按 **Unicode 码点**计算（与 `/api/v1/audits` 的 `logical_index`
  一致），列 1 起始。
- 嵌套深度上限为 256 层，超出按非法文档处理。

错误情况（均返回 `422` 且**不写入任何记录**——整个文档先解析校验通过后才逐值落库，
重复键出现在文档末尾时前面的值同样不会落库）：

| `detail.error` | 条件 |
|---|---|
| `invalid_json_document` | 非法 JSON：截断/多余内容、非法转义、`\u` 非 4 位十六进制、孤立 UTF-16 代理项、字符串内未转义控制字符、数字格式错误、嵌套超深等 |
| `duplicate_key` | 同一对象内出现重复键（按**解码后**的键名比较，`"a"` 与 `"\u0061"` 视为重复） |

```json
{
  "detail": {
    "error": "duplicate_key",
    "key": "a",
    "pointer": "",
    "offset": 9,
    "line": 1,
    "column": 10,
    "message": "duplicate object key 'a' in object <root>"
  }
}
```

`invalid_json_document` 的 `detail` 含 `offset`（出错位置的码点偏移）与
`line` / `column`（1 起始）。

### `POST /api/v1/audits/csv` — CSV 单元格公式伪装审计

接收一段**原始 CSV 文本**（`document` 字段，可选 `filename`），按以下规则解析：

- 字段以逗号分隔；双引号包围的字段内可含逗号、CR/LF 换行与 `""` 转义引号
  （解码为一个 `"`，定位到该对的第一个引号）；
- 记录以 CRLF（作为整体消费）或 LF 分隔；单独的 `\r` 视为字段内容，因此行号
  始终按分隔符所含的 `\n` 推进；
- **引号不闭合**（`unclosed_quote`，定位到起始引号）或**非法引号**
  （`illegal_quote`：未加引号的字段内出现 `"`，或闭合引号后紧跟非分隔符字符）
  返回 422，`detail` 含原文码点偏移 `offset` 与 1 起始行列 `line` / `column`。

随后逐个检查单元格：从单元格开头跳过**空格、制表符与 Unicode 双向控制符**
（即 bidi 解析器编目中的全部控制符）后，若首字符是电子表格公式触发符
`=`、`+`、`-`、`@` 之一，则报告一条命中——这正是 CSV/公式注入（以及用
不可见字符伪装绕过 `startswith("=")` 检查）的典型形态。每条命中返回：

- `record` / `field` — 1 起始的记录号与记录内字段号；
- `formula_char` / `formula_offset` / `position` — 公式起始字符及其在原文中的
  码点偏移与 1 起始行列；
- `prefix` / `prefix_controls[]` — 被跳过的前缀原文与逐字符明细（`kind` 为
  `space` / `tab` / bidi 缩写如 `RLO`，各带原文偏移 `offset` 与行列
  `position`）；
- `risk_level` — 复用 bidi 解析器对**该单元格解码后内容**给出的风险级别
  （前缀里未闭合的 RLO 会把单元格直接推到 `critical`）。

引号内换行、`""` 转义与空单元格都参与正常的记录/字段计数，不会造成记录号或
位置错位。接口**只读**：`stored: false`，不写入任何记录。

```bash
curl -s -X POST http://localhost:8000/api/v1/audits/csv \
  -H 'Content-Type: application/json' \
  -d '{"document": "name,note\r\nalice,ok\r\n  ‮=cmd,evil\r\n", "filename": "data.csv"}' | jq
```

响应（节选）：

```json
{
  "stored": false,
  "filename": "data.csv",
  "document_length": 35,
  "record_count": 3,
  "field_count": 6,
  "finding_count": 1,
  "risk_level": "critical",
  "findings": [
    {
      "record": 3,
      "field": 1,
      "formula_char": "=",
      "formula_offset": 24,
      "position": {"line": 3, "column": 4},
      "prefix": "  ‮",
      "prefix_controls": [
        {"char": " ", "codepoint": "U+0020", "kind": "space",
         "offset": 21, "position": {"line": 3, "column": 1}},
        {"char": " ", "codepoint": "U+0020", "kind": "space",
         "offset": 22, "position": {"line": 3, "column": 2}},
        {"char": "‮", "codepoint": "U+202E", "kind": "RLO",
         "offset": 23, "position": {"line": 3, "column": 3}}
      ],
      "risk_level": "critical"
    }
  ]
}
```

> 上例第 3 条记录的单元格以两个空格 + RLO（U+202E）开头伪装 `=cmd`：
> 肉眼看到的单元格像普通文本，但电子表格仍会把它当公式执行。顶层
> `risk_level` 取全部命中单元格风险的最高值（无命中时为 `info`）。

错误情况（均返回 `422`；接口只读，任何情况下都不写入记录）：

| `detail.error` | 条件 |
|---|---|
| `unclosed_quote` | 引号字段未闭合（`offset` 定位到起始引号） |
| `illegal_quote` | 未加引号的字段内出现 `"`，或闭合引号后紧跟非分隔符字符 |

缺少 `document` 字段返回 422（Pydantic 校验）。

### `POST /api/v1/identifiers/normalization` — Python 标识符 NFKC 碰撞检测

接收一段 **Python 源码**（`source` 字段，可选 `filename`），按 Python 词法规则
（参考解释器的词法器，含 [PEP 3131](https://peps.python.org/pep-3131/) Unicode
标识符）提取标识符：

- **注释、字符串字面量、数字、运算符与结构符一律跳过**；
- Python **硬关键字**（`def`、`return`、`True` 等）不作为标识符；判定前先做
  NFKC 规范化，因此全角等宽混淆拼写（如 `Ｔｒｕｅ`）也按关键字 `True` 跳过；
- 对每个保留下来的标识符原文做 **Unicode NFKC 规范化**。

仅当**同一规范形存在至少两种不同的原文拼写**时才报告碰撞：

- 同一拼写单纯重复多次 → **不是**碰撞；
- 仅大小写不同（如 `X` 与 `x`）→ NFKC 保留大小写，**不是**碰撞；
- 但全角 `Ｘ`、数学粗体 `𝐗` 与 ASCII `X` 共享规范形 `X`，或预组合 `é`（U+00E9）
  与分解形式 `e` + U+0301 共享规范形 `é`，则构成碰撞；连字 `ﬁ`（U+FB01）
  NFKC 规范化为 `fi`，同样可与 ASCII `fi` 碰撞。

每个碰撞返回规范形 `normalised`、涉及的每种原文拼写 `spellings[]`，以及每种
拼写的**全部出现位置** `occurrences[]`：`offset` / `end_offset` 为原文中的
Unicode 码点偏移（0 起始、end 排他），`line` / `column` 为 1 起始行列。
碰撞按规范形**首次出现的源码位置**排序，拼写按各自首次出现排序，每个拼写内的
出现按源码顺序排列，输出完全稳定。

碰撞报告作为**独立记录**保存（独立于 bidi 审计表），返回 `id` 后可用
`GET /api/v1/identifiers/normalization/{id}` 读取（含原始源码 `raw_source`）；
无碰撞的提交也会保存一条 `collision_count: 0` 的记录。

```bash
# 源码（注意码点差异，直接粘贴可能被输入法/编辑器归一化）：
#   café        —— 预组合 U+00E9
#   cafe\u0301  —— 'e' + 组合重音 U+0301 的分解形式
#   Ｘ          —— 全角拉丁大写 X（U+FF38）
#   \ud835\udc17 —— 数学粗体 X（U+1D417，astral 平面单码点）
curl -s -X POST http://localhost:8000/api/v1/identifiers/normalization \
  -H 'Content-Type: application/json' \
  -d '{"source": "def caf\u00e9():\n    return Ｘ + 𝐗\ncafe\u0301 = 2\n", "filename": "confusables.py"}' | jq
```

响应（节选；`offset` 为 Unicode 码点偏移，可直接在原始源码上切片复核）：

```json
{
  "id": 1,
  "stored": true,
  "filename": "confusables.py",
  "source_length": 39,
  "report": {
    "identifier_count": 4,
    "distinct_spelling_count": 4,
    "collision_count": 2,
    "collisions": [
      {
        "normalised": "café",
        "spelling_count": 2,
        "occurrence_count": 2,
        "spellings": [
          {"spelling": "café", "occurrence_count": 1,
           "occurrences": [{"offset": 4, "end_offset": 8, "line": 1, "column": 5}]},
          {"spelling": "café", "occurrence_count": 1,
           "occurrences": [{"offset": 29, "end_offset": 34, "line": 3, "column": 1}]}
        ]
      },
      {
        "normalised": "X",
        "spelling_count": 2,
        "occurrence_count": 2,
        "spellings": [
          {"spelling": "Ｘ", "occurrence_count": 1,
           "occurrences": [{"offset": 23, "end_offset": 24, "line": 2, "column": 12}]},
          {"spelling": "𝐗", "occurrence_count": 1,
           "occurrences": [{"offset": 27, "end_offset": 28, "line": 2, "column": 16}]}
        ]
      }
    ]
  }
}
```

> 上例中 `café` 的两种拼写分别是预组合 é（U+00E9）与 `e` + 组合重音 U+0301
> （终端里外观几乎相同），两个 `X` 分别是全角 U+FF38 与数学粗体 U+1D417。

按 ID 读取已保存的报告：

```bash
curl -s http://localhost:8000/api/v1/identifiers/normalization/1 | jq
```

错误情况（词法扫描失败时返回 **422**，`detail` 含出错位置的原文码点偏移
`offset` 与 `line` / `column`，且**不产生任何审计/碰撞记录**）：

| `detail.error` | 条件 |
|---|---|
| `unexpected_character` | 源码中存在 Python 词法不接受的字符（如 `$`、NUL、未依附标识符的游离组合记号），定位到该字符本身 |
| `unterminated_string` | 多行字符串（三引号等）未终止 |
| `unterminated_statement` | 单/双引号字符串未闭合（如源码以 `x = '` 结束；定位到扫描停止处——行尾或源码末尾），或源码在括号/显式续行等多行语句中途结束 |
| `indentation_error` | 缩进不一致（Tab/空格混用、unindent 不匹配等） |

```json
{
  "detail": {
    "error": "unexpected_character",
    "offset": 6,
    "line": 1,
    "column": 7,
    "message": "unexpected character '$' (U+0024) while tokenizing Python source"
  }
}
```

### `POST /api/v1/identifiers/normalization/fix-preview` — 标识符碰撞修复预览（不落库）

接收 **Python 源码**（`source`）与要修复的碰撞组 **NFKC 规范名**
（`normalised_name`），复用上面碰撞检测接口的同一套词法扫描定位该碰撞组：

- 请求里的名称自身先做一次 NFKC 规范化再匹配，因此直接传某个非规范原文拼写
  （如全角 `Ｘ`）也能定位到规范名为 `X` 的碰撞组；
- 仅当该规范名确实对应一个**碰撞组**（至少两种不同原文拼写）时才出预览；
  只有一种拼写的名称、大小写差异或完全无关的名称都返回 **422**；
- 源码词法失败同样返回 **422**（`detail` 结构与碰撞检测接口完全一致）。

修复规则：组内**已经是规范拼写的标识符原样保留、不产生编辑**；每个**非规范
拼写**的每次出现都被替换为 NFKC 规范拼写。替换只发生在词法扫描定位到的
标识符 token 区间上——

- **字符串字面量、注释、数字、关键字与其他所有字符逐字保留**（字符串/注释里
  外观相同的字符不会被动到）；
- 编辑是区间内替换，不触碰任何换行符，**前导 BOM 与换行格式（LF / CRLF）不变**；
- 非规范拼写与规范拼写的码点数可能不同（如连字 `ﬁ` 一个码点展开为 `fi` 两个、
  `e` + 组合记号两个码点折叠为 `é` 一个），替换按位置**从后向前**应用，
  因此返回的偏移始终是**原始源码**坐标。

响应包含：`edits[]`（每条编辑给出原文的 `offset` / `end_offset` 码点区间、
`original` 原拼写、`replacement` 替换文本，按源码位置升序）、修复后源码
`fixed_source`，以及对修复后源码**重新扫描**得到的碰撞报告 `report`（被修复的
组消失，其他碰撞组保留；标识符总数不变，只是改名）。该接口**只做预览**：
`stored: false`，不写入任何记录或审计行。

```bash
curl -s -X POST http://localhost:8000/api/v1/identifiers/normalization/fix-preview \
  -H 'Content-Type: application/json' \
  -d '{"source": "ﬁ = 1\nfi = ﬁ\n", "normalised_name": "fi"}' | jq
```

响应：

```json
{
  "stored": false,
  "source_length": 14,
  "target_normalised": "fi",
  "edit_count": 2,
  "fixed_source_length": 16,
  "edits": [
    {"offset": 0, "end_offset": 1, "original": "ﬁ", "replacement": "fi"},
    {"offset": 11, "end_offset": 12, "original": "ﬁ", "replacement": "fi"}
  ],
  "fixed_source": "fi = 1\nfi = fi\n",
  "report": {
    "identifier_count": 3,
    "distinct_spelling_count": 1,
    "collision_count": 0,
    "collisions": []
  }
}
```

> `edits[].offset` / `end_offset` 是 **Unicode 码点偏移**（0 起始、end 排他），
> 可直接在**原始源码**上切片复核；把各编辑按偏移从后向前应用即可无损重建
> `fixed_source`。下例中 BOM、CRLF、注释与字符串里的 `Ｘ` / `𝐗` 均保持不变，
> 只有两行真实标识符被改写：
>
> ```bash
> curl -s -X POST http://localhost:8000/api/v1/identifiers/normalization/fix-preview \
>   -H 'Content-Type: application/json' \
>   -d '{"source": "﻿# Ｘ comment\r\ns = '\''𝐗 str'\''\r\nＸ = 1\r\n𝐗 = 2\r\n",
>        "normalised_name": "X"}' | jq '.edits, .fixed_source'
> ```

错误情况（均返回 **422**，且**不保存任何预览**）：

| `detail.error` | 条件 |
|---|---|
| `collision_group_not_found` | 名称 NFKC 规范化后不对应任何碰撞组（单一拼写、仅大小写不同或名称不存在）；`detail.normalised` 给出规范化后的名称 |
| `unexpected_character` / `unterminated_string` / `unterminated_statement` / `indentation_error` | 源码词法扫描失败，`detail` 含 `offset` / `line` / `column`，与碰撞检测接口一致 |

```json
{
  "detail": {
    "error": "collision_group_not_found",
    "normalised": "foo",
    "message": "no NFKC collision group with normalised name 'foo'; a fixable group requires at least two distinct raw identifier spellings"
  }
}
```

### `POST /api/v1/identifiers/mixed-script` — 标识符拉丁/希腊/西里尔混写检测

接收 **Python 源码**（`source`，可选 `filename`），复用与 NFKC 碰撞检测**完全相同
的词法扫描**（注释、字符串、硬关键字跳过，词法失败的 422 结构一致），找出
**单个合法标识符内部混用拉丁、希腊、西里尔字母**的伪装名称（homoglyph 攻击，
例如用西里尔 `а` U+0430 冒充拉丁 `a`、用希腊 `ο` U+03BF 冒充拉丁 `o`）：

- 仅 **Unicode 字符名称以 `LATIN` / `GREEK` / `CYRILLIC` 开头**的字符计入脚本；
  组合记号、数字、下划线都是脚本中性的，不参与判定；全角（`FULLWIDTH LATIN ...`）
  与数学字母（`MATHEMATICAL ...`）等名称不以这三个前缀开头的形似字符同样不计；
- 标识符的计脚字符覆盖**两类及以上**脚本即报告；同名标识符**每次出现逐次报告**，
  全部命中按源码顺序排列。

每个命中返回原拼写 `spelling`、涉及的脚本 `scripts[]`（按拼写内首次出现排序）、
标识符自身的 `offset` / `end_offset` / `line` / `column`，以及**每个计脚字符**的
`characters[]`：`char`、`codepoint`（`U+XXXX` 形式）、`script`、原文码点偏移
`offset` 与 1 起始行列（脚本中性字符不列入，其偏移自然跳过）。该接口**只做分析**：
`stored: false`，不写入任何记录。

`docker compose up --build` 启动后在宿主机直接调用：

```bash
# 源码第一个标识符为 p + 西里尔 а（U+0430，JSON 里写作 \u0430 转义）+ y，
# 第二个为纯拉丁 pay；JSON 转义写法可避免西里尔字母被输入法/编辑器替换
curl -s -X POST http://localhost:8000/api/v1/identifiers/mixed-script \
  -H 'Content-Type: application/json' \
  -d '{"source": "p\u0430y = 1\npay = 2\n", "filename": "pay.py"}' | jq
```

响应：

```json
{
  "stored": false,
  "filename": "pay.py",
  "source_length": 16,
  "report": {
    "identifier_count": 2,
    "finding_count": 1,
    "findings": [
      {
        "spelling": "pаy",
        "scripts": ["latin", "cyrillic"],
        "offset": 0,
        "end_offset": 3,
        "line": 1,
        "column": 1,
        "characters": [
          {"char": "p", "codepoint": "U+0070", "script": "latin",
           "offset": 0, "line": 1, "column": 1},
          {"char": "а", "codepoint": "U+0430", "script": "cyrillic",
           "offset": 1, "line": 1, "column": 2},
          {"char": "y", "codepoint": "U+0079", "script": "latin",
           "offset": 2, "line": 1, "column": 3}
        ]
      }
    ]
  }
}
```

> 上例中 `pаy` 的中间字符是西里尔小写字母 а（U+0430），外观与拉丁 `a` 几乎
> 无法区分；纯拉丁的 `pay` 单一脚本，不产生命中。`offset` 为 Unicode 码点偏移，
> 可直接在原始源码上切片复核。

错误情况：源码词法扫描失败返回 **422**，`detail` 结构与标识符碰撞检测接口完全
一致（`error` 为 `unexpected_character` / `unterminated_string` /
`unterminated_statement` / `indentation_error`，含原文码点偏移 `offset` 与
`line` / `column`）；缺少 `source` 字段返回 422（Pydantic 校验）。

### `POST /api/v1/urls/query-keys` — URL 查询键歧义审计

接收一个**原始 URL**（`url` 字段），定位其查询串（第一个 `?` 之后、第一个 `#`
之前；`#` 出现在 `?` 之前时 `?` 属于片段内容，视为无查询串），按**未解码**的
`&` 切分参数、按每段**第一个** `=` 切出键（值本身可含 `=`；`&&`、首尾 `&` 产生
的零长度段无键，直接跳过；`=1` 这类空键段保留），并保留每个键在原 URL 中的
码点起止偏移（0 起始、end 排他）。

随后对每个**键**（参数值不参与）依次执行：

1. **一次**百分号 UTF-8 解码：`%XX` 十六进制三联体解码为字节、`+` 视为空格，
   拼成的字节序列按 UTF-8 解码。只解码一次——`%2520` 得到字面文本 `%20` 而非
   空格，`%2B` 是加号而非空格；原样出现的非 ASCII 字符按 UTF-8 透传；
2. **NFKC 归一化**。

当**两个及以上**参数的键归一化后相同（包括完全重复的键——即 HTTP 参数污染
形态），报告一个碰撞组。每个碰撞组给出归一化形式 `normalised` 与全部出现
`occurrences[]`：参数序号 `index`（0 起始，按保留下来的参数编号）、原始键
`raw`、解码后（归一化前）的键 `decoded`、键在原 URL 中的起止偏移
`start` / `end`。碰撞组按各自首次出现的参数序号排序，输出稳定。

**参数值从不解码、不参与比较**：值里的 `%zz`、`%FF` 等不会触发错误，相同的值
也不会构成碰撞。接口**只读**：`stored: false`，不写入任何记录。

`docker compose up --build` 启动后在宿主机 8000 端口直接调用：

```bash
curl -s -X POST http://localhost:8000/api/v1/urls/query-keys \
  -H 'Content-Type: application/json' \
  -d '{"url": "https://example.com/p?a=1&%61=2&a+b=3&a%20b=4&%EF%BC%B8=5&X=6#frag"}' | jq
```

响应：

```json
{
  "stored": false,
  "url_length": 66,
  "query": {"start": 22, "end": 61},
  "parameter_count": 6,
  "distinct_key_count": 3,
  "collision_count": 3,
  "collisions": [
    {
      "normalised": "a",
      "occurrence_count": 2,
      "occurrences": [
        {"index": 0, "raw": "a", "decoded": "a", "start": 22, "end": 23},
        {"index": 1, "raw": "%61", "decoded": "a", "start": 26, "end": 29}
      ]
    },
    {
      "normalised": "a b",
      "occurrence_count": 2,
      "occurrences": [
        {"index": 2, "raw": "a+b", "decoded": "a b", "start": 32, "end": 35},
        {"index": 3, "raw": "a%20b", "decoded": "a b", "start": 38, "end": 43}
      ]
    },
    {
      "normalised": "X",
      "occurrence_count": 2,
      "occurrences": [
        {"index": 4, "raw": "%EF%BC%B8", "decoded": "Ｘ", "start": 46, "end": 55},
        {"index": 5, "raw": "X", "decoded": "X", "start": 58, "end": 59}
      ]
    }
  ]
}
```

> 上例中 `%61` 解码为 `a`、`a+b` 与 `a%20b` 都解码为 `a b`、`%EF%BC%B8` 解码为
> 全角 `Ｘ`（U+FF38）并经 NFKC 归一化为 `X`，分别与字面键碰撞；`#frag` 是片段，
> 不参与切分。`start` / `end` 是原 URL 的码点偏移，可直接切片复核
> （`url[26:29] == "%61"`）。无查询串时 `query` 为 `null`、各计数为 0。

错误情况（均返回 **422**，响应只含 `detail`、**不输出部分报告**——所有键先完成
解码校验才汇总碰撞；接口只读，任何情况下都不写入记录）：

| `detail.error` | 条件 |
|---|---|
| `invalid_percent_encoding` | 键中 `%` 后未跟两个十六进制数字（`offset` 定位到该 `%`） |
| `invalid_utf8` | 键百分号解码后的字节序列不是合法 UTF-8（`offset` 定位到产生非法序列的 `%`） |

`detail` 同时含原 URL 码点偏移 `offset`、1 起始行列 `line` / `column`、出错参数
的序号 `parameter_index` 与 `message`；缺少 `url` 字段返回 422（Pydantic 校验）。

```json
{
  "detail": {
    "error": "invalid_utf8",
    "offset": 5,
    "line": 1,
    "column": 6,
    "parameter_index": 1,
    "message": "the percent-decoded key of parameter 1 is not valid UTF-8 (invalid continuation byte)"
  }
}
```

### `GET /api/v1/audits` — 查询历史记录

支持按风险级别精确过滤、按文件名（大小写不敏感子串）过滤与分页：

```bash
curl 'http://localhost:8000/api/v1/audits?risk_level=critical&filename=patch&limit=20&offset=0'
```

```json
{
  "total": 1,
  "limit": 20,
  "offset": 0,
  "items": [
    {"id": 7, "created_at": 1737540000.12, "filename": "patch.diff",
     "text_length": 12, "risk_level": "critical", "max_depth": 1,
     "error_count": 1, "control_count": 1}
  ]
}
```

`risk_level` 取值：`info | low | medium | high | critical`。

### `GET /api/v1/audits/{id}` — 单条详情

返回摘要、原始文本 `raw_text` 和完整解析结果 `result`。

### `GET /api/v1/audits/{id}/verify` — 重算校验

用记录中保存的 `raw_text` **重新运行 bidi 解析**，与已存储的 `result` 逐字段比较，
用于检测存储结果是否被篡改、损坏或与当前解析器版本产生漂移。接口**只读**：
只报告差异，绝不修复或改写记录。

```bash
curl -s http://localhost:8000/api/v1/audits/1/verify | jq
```

响应（存储结果被篡改过的示例）：

```json
{
  "id": 1,
  "consistent": false,
  "diff_count": 2,
  "diffs": [
    {
      "path": "/controls/0/logical_index",
      "stored": 5,
      "recomputed": 1,
      "stored_present": true,
      "recomputed_present": true
    },
    {
      "path": "/stats/orphan_closers",
      "stored": null,
      "recomputed": 0,
      "stored_present": false,
      "recomputed_present": true
    }
  ]
}
```

说明：

- `consistent` 为 `true` 且 `diffs` 为空数组表示重算结果与存储结果完全一致。
- 每条差异的 `path` 是 [RFC 6901](https://datatracker.ietf.org/doc/html/rfc6901)
  JSON Pointer，数组元素定位到下标（如 `/controls/0/logical_index`、
  `/errors/2`）；`diffs` 按 JSON Pointer 字符串排序。
- `stored` / `recomputed` 分别是保存值与重算值；`stored_present` /
  `recomputed_present` 标记该侧字段是否存在——字段缺失时对应值为 `null` 且
  `present` 为 `false`，与「字段存在但值为 `null`」（`present` 为 `true`）区分开。
- 数组长度不一致时，多出的元素按自身下标逐条报告，缺失一侧
  `present` 为 `false`。

错误情况：记录不存在返回 `404`（`{"detail": "audit record not found"}`）。

### `GET /api/v1/audits/{id}/sarif` — 导出 SARIF 2.1.0

把**已存储**的审计转换为 [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html) JSON（`Content-Type: application/sarif+json`），可直接导入 GitHub code scanning、Azure DevOps、Mend 等支持 SARIF 的代码扫描平台。

- 为每个**控制符错误**（未闭合开启符、孤立 PDF/PDI、嵌套深度超限）生成一条 result，定位到该控制符本身；
- 为每个**危险区段**（RLO/LRO 覆盖范围、未闭合区段）生成一条 result，定位到整个 `[start, end)` 区段；
- 每条 result 的 `level` 由其 `risk` 映射：`critical/high → error`、`medium → warning`、`low/info → note`（规则 `defaultConfiguration.level` 与 `properties.security-severity` 同步设置）；
- `region` 的行列均为 1 起始，**列按 UTF-16 码元逐行计算**（SARIF 规范要求），使用存储的原文重算，含 astral 字符（如 emoji，占 2 个 UTF-16 码元）时列号正确偏移；跨多行的区段同时给出 `startLine/endLine`；
- location 的 `artifactLocation.uri` 取记录中的 `filename`；缺失文件名时回退为 `audit-{id}`；
- 每条 result 带稳定 `partialFingerprints`：对「规则 id | 码点 | 起止码点范围」取 SHA-256，**不含数据库行 id**，因此同一内容重复审计产生相同指纹，便于平台做去重/回归匹配；
- `rules` 去重并按 id 排序，`results` 按（起始行、起始列、规则 id）排序，输出完全确定。

```bash
curl -s http://localhost:8000/api/v1/audits/1/sarif -o bidi-audit.sarif
```

响应（节选）：

```json
{
  "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {"driver": {"name": "bidi-audit", "version": "1.0.0",
                        "semanticVersion": "1.0.0",
                        "rules": [
      {"id": "bidi/span-RLO", "name": "DangerousRLOSpan",
       "shortDescription": {"text": "Dangerous RLO bidirectional scope (U+202E)"},
       "defaultConfiguration": {"level": "error"},
       "properties": {"tags": ["security", "unicode", "bidi",
                               "dangerous-span", "override"],
                      "security-severity": "high"}}
    ]}},
    "invocations": [{"executionSuccessful": true}],
    "results": [{
      "ruleId": "bidi/span-RLO",
      "level": "error",
      "message": {"text": "RLO override forces visual reordering of enclosed characters"},
      "locations": [{"physicalLocation": {
        "artifactLocation": {"uri": "patch.diff"},
        "region": {"startLine": 1, "startColumn": 2,
                   "endLine": 1, "endColumn": 10,
                   "snippet": {"text": "⟨RLO⟩evil.exe"}}}}],
      "partialFingerprints": {
        "bidi-audit/v1/sha256": "…sha256(rule|codepoint|start|end)…"
      }
    }]
  }]
}
```

规则 id 一览：

| ruleId | 触发条件 | 默认 level |
|---|---|---|
| `bidi/unclosed-{LRE,RLE,LRO,RLO,LRI,RLI,FSI}` | 开启符到文本结束未闭合（RLO/LRO 为 critical） | error / warning |
| `bidi/orphan-PDF` / `bidi/orphan-PDI` | 孤立闭合符，找不到对应开启符 | warning |
| `bidi/nesting-depth-limit` | 显式嵌套深度超过 125 上限（BD13） | error |
| `bidi/span-{opener}` | 危险区段（覆盖范围或未闭合区段，opener 为 RLO/LRO/LRE…） | error（RLO/LRO）/ warning |

错误情况：记录不存在返回 `404`（`{"detail": "audit record not found"}`）。清洁文本（无错误、无危险区段）导出的文档 `results` 与 `rules` 均为空数组，是合法的 SARIF「零发现」报告。

Docker 方式导出（服务在容器 8000 端口运行）：

```bash
# 宿主机直接请求并落盘
docker compose up -d --build
curl -s http://localhost:8000/api/v1/audits/1/sarif -o bidi-audit.sarif

# 或在容器内请求（与 compare 一节相同的方式）
docker compose exec bidi-audit python -c "
import json, urllib.request
doc = json.load(urllib.request.urlopen(
    'http://127.0.0.1:8000/api/v1/audits/1/sarif'))
print(json.dumps(doc, ensure_ascii=False, indent=2))
" > bidi-audit.sarif

# 仅用 docker run 时（参见上文“仅用 Docker”），把请求指向映射的 8000 端口：
docker run --rm --network host curlimages/curl \
    -s http://localhost:8000/api/v1/audits/1/sarif -o bidi-audit.sarif
```

把 `bidi-audit.sarif` 上传到代码扫描平台即可，例如 GitHub Actions：

```yaml
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: bidi-audit.sarif
```

> 提交审计时若带上仓库内相对路径作为 `filename`（如 `src/patch.diff`），SARIF location 的 `uri` 会与仓库路径一致，平台可直接在对应文件行内展示告警。

### `POST /api/v1/audits/compare` — 结果回归比较

把两条**已存储**的审计记录作为 before / after 做回归比较。控制符按
**缩写 + 出现次序**配对（例如 before 的第 2 个 RLO 对 after 的第 2 个 RLO），
多出来的出现次数分别计入新增 / 消失。

请求体：

```json
{
  "before_id": 7,
  "after_id": 12
}
```

Docker Compose 启动后直接调用（先 `docker compose up --build`）：

```bash
curl -s -X POST http://localhost:8000/api/v1/audits/compare \
  -H 'Content-Type: application/json' \
  -d '{"before_id": 7, "after_id": 12}' | jq
```

响应（节选）：

```json
{
  "before_id": 7,
  "after_id": 12,
  "changed": true,
  "risk": {
    "before": "high",
    "after": "critical",
    "changed": true,
    "direction": "escalated",
    "order_delta": 1
  },
  "error_count": {"before": 0, "after": 1, "changed": true, "delta": 1},
  "control_changes": {
    "added": [
      {
        "abbreviation": "PDF",
        "occurrence": 1,
        "control": {
          "codepoint": "U+202C",
          "abbreviation": "PDF",
          "logical_index": 8,
          "position": {"line": 1, "column": 9},
          "scope_end": null,
          "paired_with": "U+202E",
          "is_orphan": false
        }
      }
    ],
    "removed": [],
    "position_changed": [
      {
        "abbreviation": "RLO",
        "occurrence": 1,
        "logical_index": {"before": 3, "after": 1, "delta": -2},
        "position": {"before": {"line": 1, "column": 4},
                     "after": {"line": 1, "column": 2}},
        "before": {"codepoint": "U+202E", "logical_index": 3},
        "after": {"codepoint": "U+202E", "logical_index": 1}
      }
    ],
    "pairing_changed": [
      {
        "abbreviation": "RLO",
        "occurrence": 1,
        "scope_end": {"before": 10, "after": 12},
        "scope_length": {"before": 7, "after": 11},
        "paired_with": {"before": "U+202C", "after": null},
        "is_orphan": {"before": false, "after": true}
      }
    ]
  },
  "summary": {
    "before": {"id": 7, "created_at": 1737540000.12, "filename": "patch.diff",
               "text_length": 12, "risk_level": "high", "max_depth": 1,
               "error_count": 0, "control_count": 2},
    "after": {"id": 12, "created_at": 1737626400.34, "filename": "patch.diff",
              "text_length": 13, "risk_level": "critical", "max_depth": 1,
              "error_count": 1, "control_count": 2}
  }
}
```

注：上例中 `before` / `after` 子对象是对应控制符的完整信息
（与 `GET /api/v1/audits/{id}` 中 `result.controls[]` 同构，仅多一个
`occurrence` 字段），节选展示时省略了其余字段。

比较规则：

- `control_changes.added` / `removed` — 在某一侧多出来的控制符出现（含该缩写下的第几次出现，
  以及完整控制符信息），按文档逻辑顺序排列。
- `position_changed` — 配对两侧的同一出现，但 `logical_index` 不同（含行列与位移 `delta`）。
- `pairing_changed` — 配对两侧的同一出现，但 `paired_with`（配对对象）、`is_orphan`（孤立状态）
  或影响跨度长度 `scope_length = scope_end - logical_index` 发生变化。整对控制符整体平移时
  跨度不变，只会出现在 `position_changed` 中。
- `risk.direction` 为 `escalated` / `de-escalated` / `unchanged`，`order_delta` 为风险级序差。
- `summary.before` / `summary.after` 返回两侧记录的持久化摘要（id、创建时间、文件名、
  文本长度、风险级别、最大深度、错误数、控制符数）。
- 任一项不同则顶层 `changed` 为 `true`；两条记录的解析结果完全一致时为 `false`。

错误情况：

| 状态码 | 条件 |
|---|---|
| `404` | `before_id` 或 `after_id` 指向的记录不存在（detail 标明是哪一侧） |
| `422` | 两个 ID 相同，或请求体字段缺失 / 非法 |

在容器内执行（服务已在容器 8000 端口运行）：

```bash
docker compose exec bidi-audit python -c "
import json, urllib.request
req = urllib.request.Request(
    'http://127.0.0.1:8000/api/v1/audits/compare',
    data=json.dumps({'before_id': 7, 'after_id': 12}).encode(),
    headers={'Content-Type': 'application/json'})
print(json.dumps(json.load(urllib.request.urlopen(req)), ensure_ascii=False, indent=2))
"
```

### `POST /api/v1/audits/gate` — 路径风险门禁

对一组**已存储**的审计记录按文件路径执行风险门禁：每条记录按其存储的
`filename` 匹配请求中的有序路径规则，命中规则的 `max_risk` 作为该记录允许
的最高风险；记录没有文件名或文件名未命中任何规则时使用 `default_max_risk`。
实际风险不超过阈值（按 `info < low < medium < high < critical` 排序）即判定
通过。接口**只读**：不创建、不修改任何记录。

请求体：

```json
{
  "ids": [21, 22, 23],
  "default_max_risk": "medium",
  "rules": [
    {"template": "**/*.py", "max_risk": "high"},
    {"template": "docs/**", "max_risk": "info"},
    {"template": "src/**/generated/*", "max_risk": "critical"}
  ]
}
```

模板匹配规则：

- 模板与路径都按 `/` 分段；段内 `*` 匹配任意字符序列（不跨 `/`，故
  `*.py` 只匹配一段文件名），独立的 `**` 段匹配**零段或多段**（`a/**/b`
  同时匹配 `a/b`、`a/x/b`、`a/x/y/b`）；不含 `*` 的段按字面量精确匹配。
- 一条路径命中多条规则时取**固定段（不含 `*` 的段）最多**者；固定段数相同
  取**模板总段数多**者；仍相同取**请求中靠前**者。

```bash
curl -s -X POST http://localhost:8000/api/v1/audits/gate \
  -H 'Content-Type: application/json' \
  -d '{"ids": [21, 22, 23], "default_max_risk": "medium",
       "rules": [{"template": "**/*.py", "max_risk": "high"},
                 {"template": "docs/**", "max_risk": "info"}]}' | jq
```

响应（节选）：

```json
{
  "passed": false,
  "default_max_risk": "medium",
  "checked_count": 3,
  "passed_count": 2,
  "failed_count": 1,
  "risk_level": "high",
  "results": [
    {
      "id": 21,
      "filename": "src/pkg/evil.py",
      "actual_risk": "high",
      "threshold": "high",
      "matched_rule": {"index": 0, "template": "**/*.py", "max_risk": "high"},
      "used_default": false,
      "passed": true
    },
    {
      "id": 22,
      "filename": "docs/readme.md",
      "actual_risk": "low",
      "threshold": "info",
      "matched_rule": {"index": 1, "template": "docs/**", "max_risk": "info"},
      "used_default": false,
      "passed": false
    },
    {
      "id": 23,
      "filename": null,
      "actual_risk": "info",
      "threshold": "medium",
      "matched_rule": null,
      "used_default": true,
      "passed": true
    }
  ]
}
```

说明：

- `results` 按请求中 `ids` 的顺序返回；同一 ID 重复出现会逐次评估。
- 每项的 `threshold` 是实际生效的阈值（命中规则的 `max_risk` 或默认阈值），
  `matched_rule` 为命中的规则（含请求中的下标 `index`），未命中为 `null`
  且 `used_default` 为 `true`。
- 顶层 `passed` 为整体结论（全部记录通过才为 `true`）；`risk_level` 是全部
  被检记录实际风险的最高值。
- 文件名缺失（`null`）或纯空白时不参与规则匹配，直接使用默认阈值。

错误情况：

| 状态码 | 条件 |
|---|---|
| `404` | `ids` 中任一 ID 不存在（detail 含缺失的 ID，整个请求不返回部分结果） |
| `422` | `ids` 为空、风险级别非法、模板为空串或请求体字段缺失 |

### 其他

- `GET /health` — 健康检查（容器 HEALTHCHECK 使用）
- `GET /docs` / `/openapi.json` — Swagger UI 与 OpenAPI 模式

## 项目结构

```
.
├── app/
│   ├── __init__.py
│   ├── bidi.py        # UAX#9 控制符解析、配对栈、风险评级、转义预览
│   ├── diff_audit.py  # unified diff 解析（多文件/多 hunk/No-newline）+ 新增内容回映射
│   ├── json_audit.py  # 严格 JSON 解析（位置跟踪/转义解码/重复键）+ 字符串值回映射
│   ├── csv_audit.py   # CSV 解析（引号/转义/CRLF）+ 公式伪装单元格审计（只读）
│   ├── url_audit.py   # URL 查询串切分（未解码 & / =）+ 键的百分号/UTF-8 解码与 NFKC 碰撞审计（只读）
│   ├── identifiers.py # Python 标识符提取（tokenize/PEP 3131）+ NFKC 碰撞报告、码点偏移、碰撞修复预览与拉丁/希腊/西里尔混写检测
│   ├── compare.py     # 两条已存审计记录的回归比较（按缩写+出现次序配对）
│   ├── gate.py        # 路径风险门禁（分段模板匹配 * / **、规则优先级、阈值判定）
│   ├── verify.py      # 重算校验：从原文重新解析并与存储结果逐字段 diff
│   ├── sarif.py       # 已存审计 -> SARIF 2.1.0（rule/result、UTF-16 列、指纹）
│   ├── database.py    # SQLite schema / CRUD / 查询（含可选 meta_json）
│   ├── schemas.py     # Pydantic 请求模型
│   ├── main.py        # FastAPI 路由
│   └── init_db.py     # 独立初始化入口（容器启动调用）
├── tests/
│   ├── conftest.py    # 共享的临时 DB / TestClient fixture
│   ├── test_bidi.py   # 解析器单元测试 + API 冒烟测试
│   ├── test_diff_audit.py # unified diff 审计（解析/回映射/422/落库）
│   ├── test_json_audit.py # JSON 文档审计（指针/偏移/转义/代理对/重复键/422）
│   ├── test_csv_audit.py # CSV 公式伪装审计（解析/前缀/位置/422/只读）
│   ├── test_url_query_keys.py # URL 查询键歧义审计（查询串定位/切分/单次解码/NFKC 碰撞/偏移/422/只读）
│   ├── test_identifiers.py # 标识符 NFKC 碰撞（提取/关键字/码点偏移/BOM/422/独立落库）
│   ├── test_identifier_fix_preview.py # 碰撞修复预览（仅改非规范拼写/编辑偏移/重扫/BOM/CRLF/422/不落库）
│   ├── test_mixed_script.py # 标识符混写检测（脚本分类/逐字符偏移/逐次报告/BOM/CRLF/422/不落库）
│   ├── test_compare.py # 回归比较接口测试（新增/消失/位移/配对范围/404/422）
│   ├── test_gate.py   # 路径风险门禁测试（模板匹配/优先级/默认阈值/只读/404/422）
│   ├── test_verify.py  # 重算校验接口测试（一致/篡改/缺失 vs null/只读/404）
│   └── test_sarif.py  # SARIF 导出测试（level 映射/UTF-16 列/指纹/排序/404）
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── run.sh             # 本地启动脚本
└── README.md
```

## 测试

```bash
pip install pytest httpx
python -m pytest tests/ -q
```

覆盖：清洁文本、RLO 高风险、未闭合 RLO critical、LRE/PDF 配对、孤立 PDF/PDI、
LRI/PDI 隔离配对、隔离内嵌入隐式关闭、PDF 跳过隔离层（X9）、行列定位、
嵌套深度、转义预览，以及 API 的创建/详情/过滤/404；比较接口覆盖相同结果、
新增/消失、仅位置平移、配对范围变化（孤立/配对对象/跨度）、按缩写与出现次序
配对、标记配对、风险升级与错误数、以及 404 / 422 错误分支；重算校验接口覆盖
一致记录、标量/嵌套字段/数组元素篡改定位、缺失键与 null 的区分、数组长度
不一致、差异按 JSON Pointer 排序、只读性（校验不改写记录、结果幂等）与 404；
SARIF 导出覆盖
SARIF 信封与工具元数据、清洁/仅标记零发现、文件名与 `audit-{id}` 回退、
risk→level 映射（error/warning）、未闭合/平衡/孤立/隐式终止各类 rule/result、
astral 字符与跨行区段的 UTF-16 列、规则去重排序、结果确定性排序、
partialFingerprints 的稳定性与随范围/规则变化、重复审计同指纹、以及 404；
unified diff 审计覆盖多文件/多 hunk 解析、仅分析新增行（删除行与上下文行被忽略）、
按新文件行号推进与列映射、diff 行/列映射与逻辑索引保留、未闭合/孤立/隐式终止错误
与跨行危险区段回映射、每文件一条记录与汇总最高风险、No-newline 标记（行末/行中）、
CRLF、git 前缀与引号路径、重命名/删除/新增/空文件、`Binary files` 与
`GIT binary patch` 段跳过、记录 `meta` 可取回且 verify 仍一致、以及 422 分支
（空/垃圾输入、hunk 头畸形、缺文件头、体行首非法、标记非法/悬空、头部无 hunk、
hunk 行数越界指向首个越界行、截断指向 hunk 头、错误落在后续文件时全行不落库）；
JSON 文档审计覆盖字符串值递归审计（键不审计）、RFC 6901 指针（`~0`/`~1` 转义与
数组下标）、字符串 token 起止偏移、控制符/错误/危险区段回映射原文行列、
`\uXXXX` 转义与 UTF-16 代理对解码定位、普通转义与转义反斜杠不误判、
多行文档行列、根字符串、纯标量零记录、逐值落库与文件名 `#指针` 规则、
记录 verify/sarif 一致，以及 422 分支（空文档、截断、非法转义、`\u` 非十六进制、
孤立高/低代理项、字符串内未转义控制字符、数字格式错误、尾随内容、嵌套超深、
重复键含解码后重复与嵌套重复——均不落库）；路径风险门禁覆盖段内 `*`
（不跨 `/`，含 `*.py` 扩展名规则）、`**` 零段/一段/多段/连续 `**`/模板中部
与边界匹配、固定段数优先、同固定段数时总段数优先、仍同分时请求靠前优先、
未命中与无文件名回退默认阈值、阈值边界包含判定、风险排序与整体结论、
结果按请求顺序与重复 ID、只读性，以及 404（含缺失 ID）与 422 分支；
标识符 NFKC 碰撞检测覆盖按 Python 词法提取标识符（注释/字符串/数字/运算符跳过、
硬关键字与全角等宽混淆关键字跳过、软关键字保留、分解形式标识符的组合记号拼接、
astral 平面码点偏移、CRLF 与前导 BOM）、仅不同原文拼写才算碰撞（纯重复与
大小写不同不算）、fi 连字/全角/数学粗体等 NFKC 碰撞、碰撞与拼写及各拼写内
出现的源码序稳定性、码点偏移切片复核、词法失败的 422 位置（非法字符、未终止
字符串/语句、缩进错误，且不落库）、报告独立落库与按 ID 读取、404、缺字段 422
以及与 bidi 审计表的相互独立性；碰撞修复预览覆盖复用同一词法扫描定位命名碰撞组
（名称自身先 NFKC 规范化）、只替换组内非规范拼写（规范拼写零编辑）、多拼写/无
规范拼写/重复出现/连字展开与分解折叠等码点长度变化场景、编辑按源码位置升序且
偏移锚定原文、由编辑无损重建修复源码、其他字符与 BOM/CRLF/字符串/注释逐字保留、
修复后重扫（目标组消失、其他组保留、标识符总数不变），以及 422 分支（碰撞组
不存在、单一拼写、仅大小写不同、名称原始拼写规范化后无组、词法失败、缺字段/
空名称）与成功和失败均不产生任何记录、路由与按 ID 读取互不冲突；标识符混写检测
覆盖按 Unicode 名称前缀的脚本分类（仅 LATIN/GREEK/CYRILLIC 计脚，组合记号、数字、
下划线与全角/数学字母均中性）、两类及以上脚本命中、逐字符码点偏移与行列（含
BOM/CRLF/多行）、同名逐次报告与多命中源码序、字符串/注释/关键字跳过与西里尔
关键字形近词命中、词法失败 422 结构一致、缺字段 422，以及分析只读不产生任何记录；
CSV 公式伪装审计覆盖逗号分隔/双引号包围/`""` 转义/CRLF 与 LF 记录分隔（单独
`\r` 视为字段内容）解析、引号内换行与空单元格不造成记录/位置错位、空格/制表符/
双向控制符前缀跳过后的 `=`/`+`/`-`/`@` 命中、记录号/字段号与原文行列映射、
逐字符前缀明细（space/tab/bidi 缩写）、复用 bidi 解析器的单元格风险级别、
未闭合/非法引号的 422 原文行列，以及接口只读不落库；URL 查询键歧义审计覆盖
查询串定位（首个 `?`、`#` 片段终止、片段内的 `?` 不算）、按未解码 `&` / 首个
`=` 切分（值可含 `=`、零长度段跳过不占序号、空键保留）、单次百分号/UTF-8 解码
（`+` 为空格、`%2B` 为加号、`%2520` 不再二次解码、原样非 ASCII 透传）、编码后的
`%26` / `%3D` 不当分隔符、精确重复键与百分号/全角/数学字母/预组合对分解形式等
NFKC 碰撞、仅大小写不同不碰撞、碰撞组按首次出现排序、码点起止偏移切片复核、
参数值从不解码也不参与比较（值中非法编码不报错）、无效百分号编码与无效 UTF-8
的 422 原 URL 偏移/行列/参数序号（含多行 URL、首个非法键优先、出错时不输出
部分报告），以及接口只读不落库。

## 设计说明

- 审计只做**检测与呈现**，绝不返回"净化后"的文本，避免调用方误以为原文可安全渲染；
  需要人工复核时使用 `escaped_preview`。
- 控制符使用显式 Unicode 占位符（`⟨RLO⟩`）而非 `‮` 转义，使预览在终端/日志中一眼可见。
- SQLite 通过 WAL 友好的单文件方式持久化，位置由环境变量 `BIDI_DB_PATH` 控制。
