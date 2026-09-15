================================================================================
 华为麒麟990 4G  xloader（SAFE_BD_4G_xloader.bin, 192KB, Thumb-2）
 USB 下载协议（"xmodem"）完整逆向文档
================================================================================
固件   : 4G\plain\SAFE_BD_4G_xloader.bin  (196608 B = 0x30000)
基址   : 0x23000   （文件偏移 F ↔ 运行地址 0x23000+F）
帧处理器: 运行地址 0x339C4 （文件 0x109C4），函数序言 push.w {r4-r11,lr}
说明   : 任务提示的 0x33A8C（`ldrb.w r3,[r4,#0x3D8]; cmp #0xCD`）是帧处理器
         内部的 CD 分支点；真正的函数入口在其上方 0x339C4。
         该处理器经 USB 收包完成回调间接调用（blx r3 @0x3345C，经 0x339BC
         存根返回的运行期函数指针表；writeup 称 usb_init 把 usb_xmodem 注册
         为 rx_callback），故静态无直接 bl 交叉引用。
         USB 上下文: r0 = ctx；ctx+0x3D8 = 收帧缓冲(EP缓冲, 上限 0x600，
         见 0x3401C: `mov.w r3,#0x600; str r3,[r0,#0xB4]`)；
         ctx+0xB8 = 本次 USB 传输收到的字节数（= 帧总长，一次传输=一帧）。

交叉验证: (1) 本二进制静态反汇编；(2) Kirin990 白皮书 unicorn-wp.txt §2.5
         "Xmodem Protocol"；(3) BootROM/5G-xloader 同源代码副本
         (kirin9905Gexploit-main)；(4) 实机抓包 (z_route7.log：CD 应答 00/
         1f000000，0xAA/0x55 应答，196608B 整包成功)。

================================================================================
1. 帧总格式（所有帧）
================================================================================
  偏移  大小  内容
  0     1     CMD（0xFE / 0xDA / 0xED / 0xCD）
  1     1     SEQ   （序号）
  2     1     ~SEQ  （SEQ 按位取反）
  3..   n     载荷（仅 0xDA；0xFE 为 8B 固定头；0xED/0xCD 无载荷）
  3+n   2     CRC16，**大端**（高字节在前）

校验流程（帧处理器入口 0x339C8..0x33A8A）：
  * SEQ+~SEQ 必须等于 0xFF（0x339D8 `cmp r3,#0xFF`），否则
    log("[USBE]seq err, seq: %d, ~seq: %d\n"@0x45D54)（调用点 0x339E8）
    并回 1 字节 0x55（NAK）（0x33CF6→0x346E0 发送）。
  * CRC16 对 CMD..载荷（除末 2 字节外全部字节）计算，初值 0x0000，
    多项式 0x1021（CRC-16/XMODEM，即 binascii.crc_hqx(data,0)）；
    接收值按大端拼装：`ldrb.w sl,[sb,r2]`（buf[len-2]）+ `ldrb r3,[r3,#-1]`
    （buf[len-1]）→ `orr.w sl, r3, sl, lsl #8` = buf[len-1] | buf[len-2]<<8
    （0x339FC..0x33A10）。查表循环 0x33A1C..0x33A70（半字节查表，lr 初值 0）。
  * CRC 不匹配 → log("[USBE]crc err, crcgo: 0x%x, crcval: 0x%x\n"@0x45D76,
    调用点 0x33A7A，r1=收到的CRC r2=计算值）后**静默丢弃，不回复**（b 0x33D08
    → bl 0x3401C 重新武装 EP 后返回）。主机表现为超时无应答，可直接重发。

CRC 证据链：
  * 4G xloader 闪存中的半字节表 @0x45D14（16×u32 槽，u16 值）=
    标准 poly-0x1021 表 {0000,1021,2042,...,f1ef}，其后紧跟
    "[USBE]seq err..." 字符串（0x45D54）。
  * 同源 BootROM 副本同一循环用 movw/movt 装载**精确表基址**
    （bootrom dump: `movw r4,#0xEDD8; movt r4,#0`，0xEDD8=std[0]）。
  * 同源 5G xloader 副本同样（literal 0x43574 ↔ 文件 0x21574=std[0]，链接基址
    0x22000）。
  * 白皮书 §2.5 明确标注校验和为 "XMODEM-CRC"。
  * 实机：unlock990_final.py（crc_hqx 大端）对 ROM 成功整包下载 196608B
    全程 0xAA；xloader 接管后 CD 探针有应答（=CRC 通过，见 §4）。
  * 已知反常（仅记录）：4G dump 内 0x33A1C 的池字 0x33D1C=0x45D28=表基+0x14
    （若按字面执行栈表=std[5..15]+字符串，CRC 将偏离 crc_hqx——与实机行为、
    ROM/5G 同源码、白皮书全部矛盾；判定 4G dump 该字为 dump 期产物/构建差异，
    协议按 crc_hqx 定论。Python 里附了该变体作 fallback，仅当实机静默时才试）。

================================================================================
2. 分发器（0x33A8C..0x33AE4）
================================================================================
  cmd = buf[0]（即 ctx+0x3D8 首字节）
  0xCD → 0x33A94（查询，任何时候都处理，无需先收 head）
  其它: 若 ctx+0x9EC（next_seq）== 0（尚未收到 head）→
        log("[USBE]first frame not head"@0x45DCD) + **静默丢弃**（0x33AC8）
  0xDA → 0x33B7A（数据帧）
  0xED → 0x33C58（结束帧）
  其它 → 静默丢弃（b 0x33D08）

================================================================================
3. 各帧格式与语义
================================================================================
3.1 HEAD（0xFE，会话帧）—— 处理器 0x33AE6..0x33B78
    布局（14 字节）:
      [0]=0xFE [1]=0x00 [2]=0xFF [3]=FILE_TYPE
      [4..7]  = LENGTH  **大端 u32**（0x33B04..0x33B2C: buf[4]<<24|buf[5]<<16|
                buf[6]<<8|buf[7] → ctx+0x9E0）
      [8..11] = ADDRESS **大端 u32**（buf[8]<<24|buf[9]<<16|buf[10]<<8|buf[11]
                → ctx+0x9DC，并另存 ctx+0x9F4）
      [12..13]= CRC16 大端
    检查：
      * SEQ 必须为 0 且帧长必须为 14（0x33AE6: `cmp r8,#0; cmp r7,#0xE`），
        否则 log("[USBE]file frame err! seq=%d, len=%d"@0x45DE9) + 0x55。
      * FILE_TYPE ∈ {1,2}（0x33AF4: `subs r3,r1,#1; cmp r3,#1; bls ok`），
        否则 log("[USBE]file type err(%d)"@0x45E0F) + 0x55。
      * **LENGTH 与 ADDRESS 均不校验**（白皮书 §2.7.2 "Unchecked Data Length
        in Head Chunk"；本反汇编 0x33B04..0x33B78 无任何地址/长度比较，
        也没有旧版(Kirin710)的 0x07 地址错误应答）。
    状态机（0x33B4E..0x33B72）：
      total_frame_count = (LENGTH % 1024 ? 2 : 1) + LENGTH/1024  → ctx+0x9E4
        （即 数据帧数+1 个 tail；0x33B4E `ubfx r2,r3,#0,#0xA`）
      received_count = 0 (ctx+0x9E8)；next_seq = 1 (ctx+0x9EC)；ctx+0x9F0 = 0
      log("[USBI]download start! total_frame:%d"@0x45E28)
    应答：0xAA（ACK）（经 0x33C94 blo → 0x33CF2 `movs r3,#0xAA`）。
    允许会话中重发 head（0xFE 不检查会话状态）→ 重置状态机、可改地址/长度
    （白皮书 head-resend 特性）。

3.2 DATA（0xDA，数据帧）—— 处理器 0x33B7A..0x33C56
    布局: [0]=0xDA [1]=SEQ [2]=~SEQ [3..3+n]=载荷 [CRC16大端]
    SEQ 语义：
      * SEQ == next_seq → 正常。
      * SEQ == received_count（即重发上一已收帧）→ 回滚计数后重新接受
        （0x33B9C..0x33BB4，writeup §2.7.5 重发容忍）。
      * 其它 → log("[USBE]retrans seq err(%d)"@0x45E50) + 0x55。
    载荷长度检查（0x33BCA..0x33BEE）：
      * 若 next_seq == total_frame_count-1（最后数据帧）:
            期望载荷 = LENGTH - received_count*1024   （0x33BD8..0x33BE2）
      * 否则期望载荷 = 0x400（1024）。
      * 帧总长必须 == 期望载荷+5，否则 log + 0x55。
    写入（0x33C08..0x33C1A）：
      目的地址 = ADDRESS + received_count*1024
        （`ldr r3,[r4,#0x9DC]; ldr r0,[r4,#0x9E8]; add.w r0,r3,r0,lsl #10`）
      源 = ctx+0x3DB（载荷），调 0x23BE8（带重叠检测的安全
      memcpy/memmove，**无任何地址范围校验**——任意可写地址皆可写）。
    成功: received_count++、next_seq++（0x33C34..0x33C44）→ 应答 0xAA。
    （copy 返回非 0 仅打 log "[[%s] data or dev is null!]"@0x45F55 系，仍 ACK）

3.3 TAIL（0xED，结束帧）—— 处理器 0x33C58..0x33CF0
    布局（5 字节）: [0]=0xED [1]=SEQ [2]=~SEQ [3..4]=CRC16大端
    接受条件（0x33C58..0x33C5E）: SEQ == next_seq **或** 帧长==5（注意：5 字节
    的 tail 即使 SEQ 错也会被接受——实现对 5 字节帧放行），
    否则 log("[USBE]eot frame err! seq=%d, len=%d"@0x45E96) + 0x55。
    received_count++、next_seq++（0x33C6C..0x33C7E）。
    * received_count != total_frame_count（提前收尾）→
      log("[USBE]total frame wrong! cur=%d"@0x45EBB) + 0x55。
    * received_count == total_frame_count（全部完成）：
        - 应答 0xAA（0x33C9C..0x33CA8）
        - log("[USBI]expected:%d, received:%d (bytes)"@0x45EDC)
        - **记录下载目标地址**: r2 = *(*(ctx[0])+0xE34); *r2+4 = ADDRESS
          （0x33CC2..0x33CCC `str r3,[r2,#4]`，r3=ctx+0x9F4=ADDRESS）
          —— 交给外层状态机做签名校验/解密/跳转（writeup：tail 后进入 verify）。
        - 清零全部会话状态 ctx+0x9D8..0x9F4（0x33CD0..0x33CEC）。

3.4 INQUIRE（0xCD，查询帧）—— 处理器 0x33A94..0x33ABC
    布局（5 字节）: [0]=0xCD [1]=SEQ [2]=~SEQ [3..4]=CRC16大端
    处理：log("[USBI]inquire frame"@0x45DA0) →
      status = 0x41154() = *(uint8*)0x60014088（单字节！）
      → 写入 buf → usb_send(ctx, buf, **1**)（0x346E0）
      → log("[USBI]response default"@0x45DB5)。
    **xloader 应答 = 1 字节**（BootROM 的同款处理应答 4 字节 u32——
    白皮书 §2.9.5 "the inquiry command also transmits 4 bytes"；
    实机 z_route7.log：ROM 期 CD=1f000000/f11f0000 4字节，接管后 "probe 00"
    单字节——正是本代码路径）。
    状态值语义：0x60014088 在下载模式下为零初始化（全镜像唯一写者
    0x41160 ← 0x3AEB8，且该写入在充电重试路径 movs r0,#0xFE 中），
    故接管后默认应答 0x00。查询帧不受会话状态影响（已收 head 与否均可）。

================================================================================
4. 应答码汇总（上行全部为 1 字节，经 0x346E0 USB CDC 发送）
================================================================================
  0xAA  ACK —— head 成功 / 数据帧成功 / tail 完成传输
  0x55  NAK —— seq/~seq 错、head 长度或 file_type 错、数据帧长度错、
               重发 seq 错、提前收尾（total frame wrong）
  状态字节（CD 应答，默认 0x00）—— xloader 为 1 字节（ROM 为 4 字节）
  无应答（超时）—— CRC 错（"crc err"）、未收 head 前的未知帧、未知 CMD
  注意：本 4G xloader 构建**没有** 0x07（地址/大小错误）应答路径；0x07 只
  存在于旧代（Kirin710 POT 等）实现和 5G load.py 的常量定义中。

================================================================================
5. 长度 / 地址限制
================================================================================
  * 每帧载荷：非末帧必须恰为 1024；末数据帧 = LENGTH - n*1024。
    帧总长 = 载荷+5，必须 ≤ RX 缓冲 0x600(1536)（ctx+0xB4，0x3401C 设置）。
  * LENGTH（head 内 u32）与总下载量：**代码完全不校验**（白皮书漏洞
    §2.7.2）。上限只受目标 RAM 决定。
  * ADDRESS（head 内 u32）：**代码完全不校验**，直接作为 memcpy 目的
    （dst = ADDRESS + received_count*1024，0x33C08..0x33C1A → 0x23BE8）。
    可直接指定任意可写地址；xloader 本职即向 SRAM 下载 UCE、向 DDR 下载
    fastboot/BL2（白皮书 §2.2），DDR 初始化完成后 DDR 地址（如
    0x1A400000 一类）可用。写入未映射地址 → 硬 fault → USB 无响应/掉枚举
    （writeup §2.9.2 的探测方法即基于此）。
  * 会话中可重发 head 改地址/长度（head-resend）；上一数据帧可重发。

================================================================================
6. 标准会话流程
================================================================================
  host                                xloader (0x339C4)
  [FE 00 FF FT LEN(4B) ADDR(4B) CRC]  → 校验后置状态机        → 0xAA
  [DA 01 FE +1024B CRC]               → 写 ADDR+0*1024        → 0xAA
  [DA 02 FD +1024B CRC]               → 写 ADDR+1*1024        → 0xAA
  ...                                                     ...
  [DA n  .. +末帧载荷 CRC]            → 写 ADDR+(n-1)*1024    → 0xAA
  [ED n+1 ~ CRC]                      → 完成计数、记录 ADDR    → 0xAA → verify
  （任何时刻 [CD s ~s CRC] → 1 字节状态；默认 0x00）

================================================================================
7. 证据偏移速查（运行地址 = 文件偏移 + 0x23000）
================================================================================
  0x339C4  帧处理器入口  push.w {r4-r11,lr}; ldrb.w r8,[r0,#0x3D9]...
  0x339D8  cmp r3,#0xFF            （SEQ+~SEQ 检查）
  0x339E8  log seq err (0x45D54)
  0x33A1C..0x33A70  CRC 查表循环（初值 lr=0；表基 literal@0x33D1C=0x45D28⚠）
  0x33A72  cmp sl, lr              （CRC 比较；不等→静默）
  0x33A8C  ldrb.w r3,[r4,#0x3D8]; cmp r3,#0xCD   （分发）
  0x33A94..0x33ABC  0xCD 处理器（bl 0x41154; strb; bl 0x346E0 发 1 字节）
  0x33AC2  ldr.w r2,[r4,#0x9EC]; cbnz（next_seq==0 → "first frame not head"）
  0x33AE6..0x33B78  0xFE head（seq0/len14/file_type{1,2}/大端 LEN/大端 ADDR）
  0x33B4E  ubfx r2,r3,#0,#0xA      （total_frame_count = LENGTH/1024 + 1..2）
  0x33B7A..0x33C56  0xDA data（seq 重发容忍/末帧长度/写 ADDRESS+n*1024）
  0x33C08  ldr r3,[r4,#0x9DC]... add.w r0,r3,r0,lsl #10; bl 0x23BE8（写入）
  0x33C58..0x33CF0  0xED tail（完成→0xAA、记录地址、清状态）
  0x33C9C/0x33CF2  movs r3,#0xAA     0x33CF6  movs r3,#0x55
  0x346E0  usb_send(ctx, buf, len)（1 字节应答的发送器）
  0x23BE8  安全拷贝（无地址校验）
  0x41154  CD 状态读 = *(u8*)0x60014088（仅 1 字节）
  0x41160  状态写（全镜像唯一调用者 0x3AEB8，置 0xFE，非下载路径）
  0x45D14  CRC16/XMODEM 半字节表（16×u32 槽 = std poly-1021 表）
  0x45D54..0x45EDC  协议日志字符串（见 §3 各条）
  0x3401C  EP 重新武装：ctx+0xB4=0x600（收帧缓冲上限），ctx+0xBC=ctx+0x3D8
================================================================================
（⚠=反常点，详见 §1 证据链末条。除该条外，本文所有结论均为双源以上实证。）
