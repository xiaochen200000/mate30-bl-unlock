# BD 工程固件 —— xloader / BootROM 分析报告

生成时间：2026-09-09
分析对象：`BD_work\extracted\Taurus-AL00B-BD 1.0.0.33_...\Software\`（BD 工程包）
参考产物：`BOOTROM_4G_DUMP.bin`、`4G\plain\PLAIN_BD_4G_xloader.bin`、`4G\prod\PROD_4G_sec_xloader_132.bin`
分析方法：capstone 反汇编（Thumb-2）+ 递归下降控制流重建 + 逐字节容器比对

---

## 0. 结论速览

1. **BD 工程包与量产包用的是同一套镜像容器格式**（内层 "BD 头" 0x1000 字节 + 加密镜像体）。BD 工程包把 xloader 作为**裸文件**发布；量产包把它**套了一层 0xD6 字节外壳**，并且里面**装了 2 个内层镜像**。
2. BD xloader 的**明文已经拿到**（`PLAIN_BD_4G_xloader.bin`，映射基址 0x23000，0x30000 字节），这就是此前 `XL4G_FULL_DISASM.txt`（652 函数）的实际来源。本文给出更精确的入口与协议定案。
3. BD xloader 的**下载命令协议与 BootROM 是同一套**（命令字 0xCD/0xFE/0xDA/0xED，帧带 seq 与 CRC16 校验）——这解释了为什么交接前后设备都能应答同类帧。
4. BootROM 侧关键机制全部实测确认：下载地址白名单 `cmp #0x22000`（0x4E6C）、应答状态字 0x21E04 的**移位写入器**（0x4EB8）、OTP→SEB 门（0xC194 链）、ELF/裸镜像双路交接（0x912–0x93C）。
5. 修正了既有记录中的 3 处偏差（见 §5）。

---

## 1. BD 工程固件包内容与容器格式

### 1.1 文件清单（关键项）

| 文件 | 大小 | SHA256 前 16 | 说明 |
|---|---|---|---|
| `bootloaderimage/sec_usb_xloader.img` | 0x30000 | 3da1b1a89198422b | **BD xloader 容器**（本次分析主体） |
| `bootloaderimage/sec_usb_xloader2.img` | 0xD000 | 93c5dd351a7d33b2 | xloader2 / UCE 容器 |
| `bootloaderimage/sec_bl2.bin` | 0x60E00 | 1be74077f4cf9321 | BL2 容器 |
| `bootloaderimage/sec_fastboot.img` | 0x475000 | 3ac0ce9f500f87da | fastboot 容器 |
| `fastbootimage/sec_xloader.img` | 0x3F000 | — | 另一份 xloader（flash 版） |
| `4G\prod\PROD_4G_sec_xloader_132.bin` | 0x3A0D8 | 6cc9dc64edaec42d | 量产 4G xloader 容器（对照） |

### 1.2 BD 容器（内层镜像）格式 —— 0x1000 字节头

对 `sec_usb_xloader.img` / `sec_bl2.bin` / `sec_fastboot.img` 三者头结构一致：

```
+0x000  u32  0                 
+0x008  u32  1                 格式版本
+0x00C  u32  1
+0x01C  char[16] 镜像名（"xloader" / "bl2" / "fastboot"）
+0x05E  u16  0x3690            固定常量（注意：在 +0x5E，不是 +0x5C）
+0x080  u32  0xE291F358        头 magic
+0x084  u32  0x00010000
+0x088  u32  0x73
+0x08C  u32  0x00020102
+0x090  ...  每镜像不同的签名/密钥区（0x24C 字节）
+0x2CC  ...  头的第二份拷贝（结构与首份相同）
+0x740  ...  每镜像不同的第二段签名/密钥区
+0x800-0xFFF 清零
+0x1000 ...  加密镜像体（熵 7.95~8.0）
```

- 头部 0x0–0x740 是**跨镜像共享模板**：BD 工程镜像与量产镜像 A 的这 0x740 字节**逐字节相同**。
- 0x740 之后按镜像不同（覆盖镜像体的签名/密钥材料）。
- 镜像体是 CBC 类分组加密（前序研究已定案：TEE 硬件 AES + eFuse 密钥 + per-image IV），离线无法解密。

### 1.3 量产容器格式 —— 0xD6 外壳 + 两个内层镜像

`PROD_4G_sec_xloader_132.bin`（0x3A0D8）实际布局（本次新发现）：

```
+0x000  0xD6 字节外层头
        +0x00 magic 55 AA 5A A5
        +0x04 0xD6（外层头长度）
        +0x0C "HW7x27" + FFFF
        +0x18 0x3A000（内容长度字段）
        +0x1C "2020.05.07"  +0x2C "15.44.35"  +0x38 "XLOADER"
        +0x60 0x76 字节签名
+0x0D6  内层镜像 A：0x30000 字节（与 BD xloader 容器同尺寸、头 0x740 相同）
+0x300D6 内层镜像 B：0xA002 字节（同样是 BD 式头，镜像名也叫 "xloader"）
= 0x3A0D8 ✓ 与文件大小完全吻合
```

结论：**量产 xloader 容器里装着两份 "xloader" 内层镜像**，BD 工程包则把它们拆成独立文件发布（xloader / xloader2 等）。两者格式同源。

> 待定项：A 的镜像体密文与 BD 镜像体密文完全不同（12032/12032 个 16B 块全不同）。这可能是同一明文的两次不同加密（不同 IV/签名），也可能是不同构建。离线无法判定；能确定的是**尺寸与头模板完全一致**。

---

## 2. BD xloader 分析

### 2.1 明文映射

- 文件：`4G\plain\PLAIN_BD_4G_xloader.bin`（0x30000 字节）
- 映射基址：**VA 0x23000**（文件偏移 = VA − 0x23000）
- 佐证：容器头 0x1000 + 镜像体 0x2F000 = 0x30000；镜像体起始（VA 0x23000）即 `XL4G_FULL_DISASM.txt` 所用基址；`XLOADER_4G_PATCHED_FULL.bin` = 该容器头 + 解密体 + 5 处研究补丁（与明文仅差 12 个字，全在已知补丁点）。

### 2.2 镜像头（VA 0x23000 起，0x154 字节）—— 段表 + 入口跳板

段表按 8 字（32B）记录解读，可得到**自洽的段布局**：

| 段 | VA | 大小 | 结束 |
|---|---|---|---|
| 头 | 0x23000 | 0x154 | 0x23154 |
| 段1 | 0x23154 | 0x27BF0 | 0x4AD44 |
| 段2 | 0x4AD44 | 0x72BC | 0x52000 |

0x154 + 0x27BF0 + 0x72BC = **0x2F000** ✓（正好等于镜像体大小）

**入口跳板在头内 0x23140**（关键修正）：

```
0x23140: bl #0x23150
0x23144: bl #0x23150
0x23148: "XLOADER!"            ; 8 字节横幅字符串
0x23150: bl #0x23158
0x23154: b .                   ; ★ 死循环陷阱（段1 首 4 字节）
0x23156: nop
0x23158: push {r0,r1,r2,r4,r5,lr}   ; main 初始化序列开始
0x2315A: bl #0x246FC ...       ; 22 个模块初始化调用
```

- 既有记录写的 "entry 0x23154" 实为**段 1 的起始 VA**；0x23154 处是 `b .` 陷阱，真正的可执行入口是 **0x23140**（跳板）→ 0x23150 → 0x23158。
- 段表 + 跳板 = 镜像自描述结构；跳到段 1 起点会原地死循环，这可能是刻意的"错误入口自锁"设计。

### 2.3 代码规模（本次重建）

- 函数前导（push 类）候选：884
- 可解析 BL 目标：973；其中"既是前导又被调用"的强函数：588
- 前序 `XL4G_FULL_DISASM.txt`：652 函数（含库函数/尾调）

### 2.4 ★ 下载命令协议（VA 0x339C4，函数从 0x339C4 起）

这是 BD xloader 与主机/USB 引擎对话的核心，也是 **CD 应答的来源**。本次完整展开：

```
0x339C4: push.w {...}
0x339C8: ldrb.w r8, [r0,#0x3D9]      ; 长度字节1
0x339CC: ldrb.w r2, [r0,#0x3DA]      ; 长度字节2
0x339D2: add r3, r8, r2
0x339D8: cmp r3, #0xFF               ; 帧长门：两长度字节之和须为 0xFF
0x339E6: beq 0x339FC                 ;   不满足 → 报错返回
0x339FC: r2 = r7-2                    ; r7 = [ctx+0xB8] 帧总长
0x33A02: sl = (buf[len-2]<<8) | buf[len-1]   ; 帧尾 16 位校验值
0x33A16..0x33A70: 查表法 16 位校验循环
                 （表在 VA 0x45D14 附近，值 0x0000,0x1021,0x2042,0x3063,...
                   即 CRC-16/CCITT 多项式 0x1021 的 nibble 表）
0x33A72: cmp sl, lr
0x33A74: beq 0x33A8C                 ; 校验通过 → 分发
0x33A8C: r3 = buf[0]                 ; 命令字节（ctx+0x3D8）
0x33A90: cmp r3, #0xCD               ; ← CD 命令
0x33A92: bne 0x33ABE
   ── 0xCD 处理：
   0x33AA4: bl #0x41154              ; getter：读 1 字节
   0x33AAA: strb.w r0, [r4,#0x3D8]   ; 应答写回 buf[0]
   0x33AB2: bl #0x346E0              ; 发送应答（1 字节）
0x33ABE: cmp r3, #0xFE ; beq 0x33AE6 ; ← HEAD 帧
0x33ADA: cmp r3, #0xDA ; beq 0x33B7A ; ← 数据/搬运帧
0x33ADE: cmp r3, #0xED ; beq 0x33C58 ; ← 结束帧
```

配套字符串（VA 0x45D54 起）直接印证协议语义：

```
[USBE]seq err, seq: %d, ~seq: %d
[USBE]crc err, crcgo: 0x%x, crcval: 0x%x
[USBI]inquire frame
[USBI]response default
[USBE]first frame not head
[USBE]file frame err! seq=%d, len=%d
[USBE]file type err(%d)
[USBI]download start! total_frame:%d
[USBE]retrans seq err(%d)
```

**getter / setter（0x41154 / 0x41160）—— 原厂实现：**

```
0x41154: ldr r3,[pc,#4]      ; r3 = *(0x4115C)
0x41156: ldrb r0,[r3]        ; 读 1 字节
0x41158: bx lr
0x4115C: .word 0x60014088    ; ★ 原厂目标 = 0x60014088（SRAM/寄存器别名区）
0x41160: ldr r3,[pc,#4]      ; setter
0x41162: strb r0,[r3]
0x41164: bx lr
```

- 原厂 CD 应答 = **从 0x60014088 读 1 字节**（这就是"4Bps 一字节应答"的来源）。
- 前序研究把 0x4115C 字面量改成 `0x23000`（G_PTR）以读取解密镜像首字节——对应记录中的 "0x41156 ldrb→ldr / 0x4115C literal→G_PTR"。

### 2.5 xloader 的安全/引导链（字符串定位）

| VA | 字符串 | 含义 |
|---|---|---|
| 0x42FE3 | `vrl_backup` / `GetVrlErr` / `RdVrl fail` / `ChkVrlErr` | VRL 头读取与校验 |
| 0x4309D | `normalboot` | 正常启动路径 |
| 0x430C1 | `Flash boot mode to read uce!` | flash 启动读 UCE |
| 0x430EC | `xloader main download mode to read uce!` | 下载模式读 UCE |
| 0x4312D | `Flash boot mode to read fastboot!` | flash 启动读 fastboot |
| 0x4315E | `xloader main download mode to get fastboot!` | 下载模式取 fastboot |
| 0x431B0 | `xloader3 SecErr:0x%x 0x%x` | xloader3 安全校验失败 |
| 0x431FC | `xloader3` / `xloader3 verify fail` | 第三级加载器 |
| 0x43234 | `BOOTMAGICNUMBER!` | 镜像魔数校验 |
| 0x434B8 | `efuse err` | eFuse 读取 |
| 0x43DB5 | `head_check_fail` | 头部校验 |
| 0x44848 | `UceLenErr%d` / `wait uce start failed` | UCE 启动 |

结论：xloader 自身实现了一条 `VRL → xloader3 → bl2/fastboot/UCE` 的多级加载链，并在下载模式下复用 BootROM 的 USBE 帧协议。

---

## 3. BootROM 分析（`BOOTROM_4G_DUMP.bin`，0x14000）

### 3.1 向量表与复位

```
0x000  SP     = 0x0005D3FC      （栈顶；下载单槽 = SP-0x34 = 0x5D3C8）
0x004  Reset  = 0x00000049 → 0x48
0x008+ 其余异常向量全部 = 0xB5（保留/占位）
```

复位代码（0x48）：

```
0x48: ldr r1,[pc,#0x120]   ; r1 = *(0x16C) = 0x4021B000   （SoC 系统寄存器基址）
0x4A: ldr r2,[r1,#8]       ; 启动状态字
0x4C: tst r2,#1
0x50: bne 0xAA             ; 从核/热启动 → 0xAA（间接跳转 *(*(0x178)+4)）
0x54: ldr r3,[pc,#0x118]   ; 0xDEAD0000（掩码）
0x56: ldr r4,[pc,#0x11C]   ; 0xFFFF0000
0x58: ldr r2,[pc,#0x110]   ; 0x4021B000
0x5A: ldr.w r1,[r2,#0x40C] ; 启动模式寄存器
0x5E: ands r1,r4
0x60: cmp r1,r3
0x62: beq 0xAA             ; 已标记 → 跳 0xAA
0x66: bl #0x74             ; 清空全部通用寄存器
0x6A: mov.w r0,#0
0x6E: bl #0x85C            ; ★ 进主启动流程（r0=0）
0x72: b .                  ; 不应返回
```

### 3.2 主流程 0x85C（r6 = 入参）

```
0x85C: 清零 *0x21E04（CD 状态字）与 *0x21E98（OTP 标志）
0x884: 打印 "Rom\n"（字符串 0xF3E8）
0x898-0x8D6: CRG 时钟初始化
      0x4022A400 |= 1、0x4022A004 |= 1、0x4021C828 &= ~3、0x4021B31C |= 0x80008000
0x8DC: sb = 0x50F8()
0x8E2: if (r6 != 0) → 0xA30（另一条路径：置状态 0x1F、r6=1、回 0x8EE）
0x8E8: r8 = 0x3B4()          ; ★ ver_mode：读 0x40285114 & 3
                             ;    ==0 → 打印 "normal\n"（0xF230）并推状态字节 0x1F，返回 0
                             ;    !=0 → 打印 "download\n"（0xF238），返回 1
0x90A: if (r8 == 1) → 0x944  ; 走额外检查 0x770
0x910: if (r8 == 0) → 0x950  ; 直接进镜像检查
```

存储介质判定 0x3EC：读 `0x4021B3A0 & 0x8000` → 1 = UFS（打印 "ufs\n"），0 = NVMe（打印 "nvme\n"）。
`0x770` 按介质分派：UFS → `0x6FC`，NVMe → `0x23B0`，**把 flash 镜像读入 0x22000**（0x6FC 以 0x8000 为单位读，末尾字 `[r6+0xFFC]` 作长度续读）。

### 3.3 镜像校验（0xBCDC + 0x56A8 + 0x5DF4）

```
0x950: if (0x6AC(0x22000) != 0) → 0xA1C   ; 0x6AC：取 download_image_addr，须 == 0x22000
0x95E: if (0xBCDC(0x22000, &sp) != 0) → 0xA02
0xBCDC: 0x56A8(sp, 1, 0x3C)        ; 读 0x3C 字节描述符
        (hdr>>16)&3 == 1 ?         ; 类型门（否则直接返回 0）
        (hdr>>18)&3 <= (img[0x5C]&3)   ; 否则返回 0xF0000009
        (hdr>>20)&3 <= ((img[0x5C]>>2)&3) ; 否则返回 0xF000000A
        (img[0x5C]&3) == 0 → 直接返回 0（跳过 0x5DF4）
        否则 0x5DF4(...) 须返回 0x5A5A  ; SEB 验签
0x9EE: 0x45C(...) == 0             ; secure_init（SEB/GM 分派）
0x45C: 0x2A4()、0xBB4C()、0xC194() ; 见 3.5
0xA78: 0x5C38(...) == 0            ; DICE
0xA80: beq.w 0x912                 ; ★ 全部通过 → 进最终交接
```

### 3.4 ★ 最终交接（0x912–0x93C）

```
0x912: mov.w r0,#0x22000
0x916: bl #0x420                   ; 判 0x23000 处是否 ELF
0x91A: lsls r1, r0, #0x1C          ; 取返回值低 4 位
0x91E: r4 = 0x00023001  (eq)       ; 非 ELF → 目标 = 0x23000|1
0x928: r3 = 0x23000                ; ELF 分支：
0x92C: r4 = *(r3+0x18)             ;   r4 = ELF64 e_entry
0x92E: adds r4,#1
0x930: 打印 "exc_xloader!"（0xF460）
0x93C: blx r4                      ; ★ 交接
```

`0x420` 的实现：

```
0x422: r3 = r0 - 0x20000; if (r3 > 0x3E000) return 0x10000
0x432: r1 = 0xF254                 ; ROM 内常量 "\x7FELF"
0x436: r0 += 0x1000                ; → 0x23000
0x440: bl 0x51F8                   ; memcmp(0x23000, "\x7FELF", 4)
      相等 → 打印 "elf\n"（0xF25C），返回 0xF
      不等 → 返回 0
```

即：**解密镜像落在 0x23000**；ELF 镜像用 `e_entry` 进入，非 ELF（裸镜像）进入 0x23000|1。

> 注意（待定项）：BD xloader 的镜像体在 0x23000 处是 0x154 字节段表 + 0x23140 跳板（见 §2.2），并非可直接执行的裸入口；而段表首字节 `01 00 00 00` 反汇编为 `str r0,[r0]` 类非法访存。因此"非 ELF → 0x23000|1"这条分支在真实链路里对应的镜像类型仍需实验确认（可能与 xloader3 裸镜像或 UCE 镜像配对；xloader 本体实际是从 0x23140 跳板进入的）。

### 3.5 ★ OTP / SEB 安全门（0xC194 链）

```
0x496: bl #0xC194
0xC194: r0 = 0x7470()              ; OTP 读取（0x7470 操作 0x40285050/0x40285150 寄存器块）
        期望返回值 0x5A5A           ; 不匹配 → 直接返回
0xC1A6: r0 = 0x5D8C(5)             ; SEB 安全初始化（模式 5）
0x5D8C: *0x21E90 = 0x5D800         ; 把 0x5D800 写进 SRAM 配置槽
        依次调用 0x80E4、0x6AA4、0x6D3C、0x6AAC、0x614C、0x6D44
        每一步都须返回 0x5A5A
0xC1AC: 若返回值 == 0x5A5A:
0xC1B2:   *0x21E98 = 0x5A           ; ★ 置"OTP/SEB 门通过"标志
        否则 0x7800() 报错返回
```

- 0x21E98 = OTP/SEB 门标志（0x5A = 通过），由 0x85C 在启动时清零。
- 0x21E04 = CD 应答状态字，写入器 0x4EB8：

```
0x4EB8: r3 = 0x21E04; r2 = *r3
        if (r2 & 0xFF000000)  → 清低字节并写入 r0（第 4 次起覆盖低字节）
        else                  → *r3 = (r2 << 8) | r0（逐字节左移推进）
```

即它是**移位式 4 字节应答字**：每次调用把新字节压入，前 3 次形成 `??..xx`、`??xxxx`、`xxxxxx`，第 4 次起低字节被替换——与既有记录中的 `1f000000` / `f1f1f11f` / `ccba11ca` 现象吻合。读取器 0x4EDC 直接返回 `*0x21E04`。

### 3.6 USB 下载协议（HEAD 解析 0x4B64 区）

- 地址解析：ctx+0x3E0..0x3E3 按**大端**拼出 32 位地址 `r1`，与 **0x22000** 比较（0x4E6C `cmp.w r1,#0x22000`）；ctx+0x3DC..0x3DF 拼出第二个 32 位量 `r3`（长度/标志）。
  - 不等 → 打印 `[UE]file addr err:%x`（0xFA04），置 `fp=7` 后跳 0x4D38（既有实测：仍会回 ACK，但数据被丢弃 —— 即记录中的 bug2）。
  - 相等 → 计算对齐后长度 `r3 = ((r3&0x3FF)?2:1) + (r3>>10)`，写回 ctx+0x9DC/0x9E4/0x9F4 等。
- ROM 侧同名字符串：`[UE]command timeout! %x:%x`、`[UE]download err`、`[UE]wait frame timeout`、`[UE]wait enum timeout`、`[UE]crc err`、`[UE]file addr err`。
- 关键 SRAM 地址：下载缓冲 0x22000、解密目标 0x23000、应答状态字 0x21E04、OTP 标志 0x21E98、SEB 槽 0x21E90。

### 3.7 其它已确认的小函数

| 地址 | 作用 |
|---|---|
| 0x420 | ELF 判定（见 3.4） |
| 0x45C | secure_init 总入口（SEB/GM 分派） |
| 0x6AC | 检查 download_image_addr 是否 == 0x22000（0x38D0 取值） |
| 0x6FC / 0x23B0 | UFS / NVMe 读镜像到 0x22000 |
| 0x770 | 按介质分派加载 |
| 0x4EB8 / 0x4EDC | 0x21E04 写入器 / 读取器 |
| 0x51C8 / 0x51F8 | memset / memcmp |
| 0x5C2C | 蹦床：`bl 0x51C8; add sp,#0x24; ldr pc,[sp],#4` |
| 0x5C38 | DICE 流程 |
| 0x673C | 返回码常量函数：`movs r0,#0x5A; pop {r4,r5,r6,pc}`（不是"ret-slot 触发点"） |
| 0x7470 | OTP 读取（0x40285050 块） |
| 0x5D8C | SEB 初始化（模式 5，写 0x21E90=0x5D800） |
| 0xC194 | OTP→SEB 门（见 3.5） |

---

## 4. 两套固件的对照

| 维度 | BD 工程 xloader | 量产 xloader 132 |
|---|---|---|
| 发布形态 | 裸容器 0x30000 | 0xD6 外壳 + 2 个内层镜像（0x30000 + 0xA002） |
| 内层头 0x0–0x740 | 相同 | 相同（逐字节） |
| 内层头 0x740+ | 按镜像不同 | 按镜像不同 |
| 镜像体 | CBC 加密（已解密得到明文） | CBC 加密（密文不同，离线不可解） |
| 代码分析 | `PLAIN_BD_4G_xloader.bin` 652 函数 | 无独立明文；同格式同尺寸 |

---

## 5. 对既有记录的修正

1. **入口不是 0x23154**：0x23154 是段 1 起始 VA，且该处是 `b .` 陷阱；可执行入口是 0x23140 跳板（→0x23150→0x23158 main）。
2. **ver_mode 分支**：`r8=1 → 0x944`，`r8=0 → 0x950`；0x912/0x916（ELF 判定 + `blx`）**只在 DICE（0x5C38）通过后由 0xA78 跳入**，不是 ver_mode 的直接分支。此前"0x916 在舞步路径从不触发"的根因需要按新控制流重新评估。
3. **0x673C 不是 ret-slot 触发点**：它是返回 0x5A 的常量小函数（0x66FC 函数群的返回码路径）。
4. **0x3690 字段在 +0x5E**（u16），此前按 +0x5C 读取会错位 2 字节（这也是此前"量产容器内嵌 BD 镜像"比对差 2 字节的原因）。
5. **量产容器是双镜像结构**（A 0x30000 + B 0xA002），外层头 0xD6 字节。

---

## 6. 待办 / 建议验证项

1. 用 0x23018（ELF e_entry）与非 ELF 分支的实际镜像类型做一次实机确认（谁进 0x23000|1、谁进 e_entry）。
2. 量产镜像 A 与 BD 镜像体明文是否同一份：需要设备侧解密后比对（或从 SRAM 读回）。
3. xloader 段表（0x23000 起 0x154 字节）与 VRL 头字段的对应关系（段表 8 字记录 vs VRL 结构体）值得单独建模——它直接决定打补丁时哪些字节会破坏校验。
4. CD 应答链路：xloader 侧 0x41154 getter 原厂读 0x60014088，改成读 0x23000 后需要确认 0x60014088 本身是什么外设/SRAM 槽（关系到"原厂为何返回 1 字节"）。

---

## 附录：本次分析的产出文件

| 文件 | 内容 |
|---|---|
| `z_bd_analyze\a1_out.txt` | 文件清单与哈希 |
| `z_bd_analyze\a2_out.txt` | 各镜像头 0x80 字节 + 4K 熵分布 |
| `z_bd_analyze\a7_xldiff.py` 输出 | BD 明文 vs 量产补丁明文逐字比对（12 字差异） |
| `z_bd_analyze\a8_xlbody.txt` | xloader 函数普查 + 关键区域反汇编 + 字符串 |
| `z_bd_analyze\a10_bootrom.txt` | BootROM 向量表/函数普查/关键区域反汇编 |
| `z_bd_analyze\a11_bootrom2.txt` | 白名单/0x420/舞步/OTP 链展开 |
| `z_bd_analyze\a12_bootrom3.txt` | ROM 数据区字符串 + 引导函数 |
| `z_bd_analyze\a13_bootrom4.txt` | 调用关系 + 主流程 |
| `z_bd_analyze\a14_bootrom5.txt` | 加载后路径 + 分支字节核对 |
| `z_bd_analyze\a16b_recursive.py` | 递归下降反汇编器 + 关键常量交叉引用 |
| `z_bd_analyze\a19b_align.py` | 量产/BD 容器精确对齐比对 |
| `z_bd_analyze\a20_twoimg.py` | 双镜像结构验证 |
| `z_bd_analyze\a21_dispatch.py` | xloader 命令协议完整反汇编 |
