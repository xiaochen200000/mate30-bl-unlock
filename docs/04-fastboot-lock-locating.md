# 麒麟990 fastboot 锁位/解锁函数定位方法论（LOCK_METHOD）

> 适用对象：华为海思麒麟990（TAS-AL00 4G / ELSP / LIO 等同源平台）fastboot 明文 dump。
> 实证样本：`elspfastboot_complete_dump.bin`（ELSP 工程机，0x4E2000 字节，6649 函数）
> 与 `liofastbootdec.bin`（LIO 工程机，0x500000 字节，6424 函数）。
> 加载基址均为 **0x3A400000**，ARM64 小端，文件偏移 = VA − 0x3A400000（全文件线性映射）。
> 本文所有地址/指令字均经 capstone AARCH64 反汇编实证（脚本 m02–m08，见附录）。
> 置信度标注：【实证】= 反汇编+字符串 xref 双重验证；【推断】= 由结构/调用关系推出，未见终验。

---

## 0. 一页速查（4G dump 到手后的"秒级"流程）

```
① 定位 'userlock=unlocked ' / 'FAILcheck password failed!' / 'no_module: %s:userlock_hamc unlock error'
② 对字符串 VA 做全文件 QWORD 指针扫描 + ADRP+ADD 扫描 → 找到引用函数
③ 沿 {name,handler} 命令表 / bl 调用链回溯到命令处理函数
④ 套用第 5 节补丁模板（密码校验/门控/写路径三类补丁点）
```
判定分叉：**4G 明文里搜 `FAILcheck password failed!`** —— 有 → 走 ELSP 经典路径（第 5.1 节）；
无但 `userlock=unlocked ` 有 → 走 LIO 式路径（第 5.2 节）；两者皆无 → 平台版本更老，退回通用锚点（第 6.3 节）。

---

## 1. 锚点清单（全部为 C 字符串，ASCII，无宽字符）

### 1.1 两样本共有（量产 fastboot 大概率保留）
| 锚点字符串 | ELSP VA | LIO VA | 引用函数（作用） |
|---|---|---|---|
| `userlock=unlocked ` | 0x3A642080 | 0x3A620220 | ELSP: creat_userlock_cmdline / LIO: create_manufacture_secure_cmdline —— **启动时向 kernel cmdline 报锁态** |
| `userlock=relocked ` | 0x3A642098 | 0x3A620238 | 同上 |
| `userlock=locked ` | 0x3A6420B0 | 0x3A620250 | 同上 |
| `oem unlock` | 0x3A63AC90 | 0x3A617640 | fastboot_cmd_lock_state_chk（命令门控）+ 命令表 |
| `flashing unlock` | 0x3A63ACB0 | 0x3A617650 | 同上 |
| `PHONE Locked` / `PHONE Unlocked` / `PHONE Relocked` | 0x3A6419C0/0x3A641A40/0x3A641AC0 | 0x3A617740/0x3A6177B8/0x3A617838 | get_lock_state_string —— `oem get-bootinfo` 输出 |
| `INFOitem: userlock, status: %s, credible: Y` | 0x3A641228 | 0x3A61FC20 | ELSP: common_oem_check_root_info / LIO: oem_check_root_info |
| `huawei_userlock: cannot get oeminfo root type info` | 0x3A641280 | 0x3A61FCE0 | oeminfo_root_type_info（读 oeminfo item 0x43，root type） |
| `huawei_fblock: hwdog_certify->lock_state.fb_lock_stat = %d` | 0x3A6416F8 | （LIO 变体文本） | fastboot_lock_stat_initial —— **锁状态初始化** |
| `try remove write protect 8M/16M` | 0x3A643048 附近 | 0x3A61FDC8 附近 | lock_state_locked/unlocked、disable_oeminfo_write_protect —— **oeminfo 分区写保护管理** |
| `hisi_avb: fail to get lock state` | 0x3A6A2508 | 0x3A678408 | hisi_avb_is_device_unlocked |
| `secboot` / `crypto` / `fastboot_ctrl`（操作符注册名） | 有 | 有 | get_operators() 注册表查找，用于 HMAC/锁态查询 |

### 1.2 ELSP 独有（经典 `oem unlock <key>` 密码路径存在判据）
| 锚点字符串 | ELSP VA | 指向 |
|---|---|---|
| `FAILalready fastboot unlocked` | 0x3A6413E0 | common_usr_fastboot_unlock+0x148（已解锁门控） |
| `FAILcheck password failed!` | 0x3A641400 | common_usr_fastboot_unlock+0x164 / common_usr_fastboot_relock+0x110（**密码校验失败分支**） |
| `FAILYou choose not to unlock the phone` | 0x3A641420 | common_usr_fastboot_unlock+0x270（GUI 拒绝分支） |
| `FAILdevice will reboot after 30S due to 5 times of wrong key.` | 0x3A63B158 | 密码错误计数>4 分支（计数器全局变量 0x3A825484 / relock 用 0x3A825488） |
| `userlock_hmac`（日志 tag） | 0x3A610408 | userlock_hmac.constprop.8 / common_lock_stat_write |
| `no_module: %s:userlock_hamc unlock error` | 0x3A642AD0 | common_lock_stat_write+0x120（**解锁写 oeminfo 失败分支**） |
| `no_module: %s:oeminfo lock state not match!` | 0x3A642BA0 | common_lock_stat_write+0xB0 |
| `huawei_userlock: write oeminfo user stat info failed` | 0x3A6414C0 | common_usr_fastboot_unlock+0x2B0 / relock+0x320 |
| `no_module: verify type not match.` / `no_module: cannot get OEMINFO_HWSB_AES_PWD info` / `no_module: operate password_PBK_SHA256_RSA_check fail.` | 0x3A642D98/0x3A642D20/0x3A642E58 | isec_userlock_check（**密码校验函数本体**） |
| `ABABCDCDEF` / `EFEFABCDEF` | 0x3A642AB0/0x3A642AC0 | HMAC 魔串：解锁/回锁 |

### 1.3 LIO 独有（经典路径被裁、RSA 票据路径判据）
| 锚点字符串 | LIO VA | 指向 |
|---|---|---|
| `FAILpassword not match` | 0x3A61F3A8 | flash:slock 处理器 0x3A4209A0（RSA 票据校验失败分支） |
| `FAILfb lockstat not unlocked` | 0x3A61F4F8 | cmd_hwdog_certify_set+0x130 |
| `INFO FB LockState: ` / `INFO USER LockState: ` | 0x3A61A070/0x3A61E698 | cmd_hwdog_certify_info（`oem lock-state info` 处理器） |
| `huawei_userlock: try remove write protect 8M/16M` | 0x3A61FDC8/0x3A61FE28 | LIO userlock 写保护模块 |

---

## 2. xref 步骤（无符号表也能跑）

工具：`m02_analyze.py`（本目录），核心两步：

1. **字符串定位**：在文件内搜锚点 ASCII（注意 `[cpu%d][%d ms]` 前缀版本与裸版本各一份，取**裸版本**VA）。
2. **代码引用回溯**（两种都要做）：
   - **ADRP+ADD 立即数配对**：线性反汇编 .text（0x3A400000 ~ .text 末尾，capstone 遇到字面量池要**跳 4 字节重启**，否则第一处 pool 就中断——这是本库脚本踩过的坑），记录 `adrp Xn,#page` → 4 条指令内 `add Xn,Xn,#imm`，page+imm == 字符串 VA 即命中。命中点用符号区间二分定位所属函数。
   - **QWORD 数据指针扫描**：全文件按 4 字节步进搜 8 字节小端 == 字符串 VA。命中多为**命令表 name 槽**（ELSP: 0x3A7F1EA0；LIO: 0x3A7A9F98/0x3A7AA1A8），**name 槽 +8 即 handler 函数指针**（ELSP 表布局 `{name_ptr, fn_ptr}` stride 0x10）。
3. **stub 解链**：ELSP/LIO 大量 4 字节 stub（`usr_fastboot_unlock`、`cmd_lock_stat_info` 等），首指令 `B <target>`（0x14xxxxxx），直接跳到实函数。
4. **调用图**：对关键函数做全 .text `bl` 扫描得 caller 列表（m02_*_callers.txt）；无 BL caller 的（fastboot_unlock_execute_func、命令处理器）由 ops 结构体函数指针调用——再对函数 VA 做 QWORD 指针扫描定位 ops 结构（ELSP ops: 0x3A7F1DD0 区；LIO ops: 0x3A7AA0E8 区）。

### 2.1 命令表（实证布局）
**ELSP**：运行时指针全局 `0x3A81FC00`（文件静态值即 0x3A7F1E30），13 项 `{name_ptr, fn_ptr}` stride 0x10：
```
[7] 'oem unlock'     -> 0x3A41CFAC usr_fastboot_unlock  (stub) -> B 0x3A41B0B8 common_usr_fastboot_unlock
[9] 'flashing unlock'-> 同上
[8] 'oem relock'     -> 0x3A41CFB0 usr_fastboot_relock  (stub) -> B 0x3A41B3B4 common_usr_fastboot_relock
[10]'flashing lock'  -> 同上
[4]'oem get-bootinfo'-> 0x3A41D52C (stub)-> common_cmd_lock_stat_info 0x3A41BA68
[5]'oem check-rootinfo'-> 0x3A41D530 (stub)-> common_oem_check_root_info 0x3A41AAD8
```
另有 oem 子命令表 `0x3A7F1740`（70 项 {name,len,fn} stride 0x18，`oem poweronlock_unlock` 等）。
ELSP ops 结构（0x3A7F1DD0..0x3A7F1E30）：`cmd_hwdog_certify_init, get_lock_state_string(0x3A41BBDC),
get_lock_state_for_verifyboot, fastboot_cmd_lock_state_chk(0x3A41BE6C), fastboot_unlock_execute_func(0x3A40F3D0),
get_frp_lock_state_string, is_frp_open, get_bootinfo_lock_status, get_bootinfo_fblock_status`。

**LIO**：指针全局 `0x3A7D3EF0`（静态值 0x3A7AA138），13 项同布局，但 **`oem unlock`/`oem relock`/`flashing unlock`/`flashing lock` 四项被移除**（新增 'oem hwdog certify set'）。
LIO ops 结构 0x3A7AA0E8：`cmd_hwdog_certify_init(0x3A40FFB8), ?, get_lock_state_string(0x3A40F408),
get_lock_state_for_verifyboot(0x3A40FB9C), fastboot_cmd_lock_state_chk(0x3A40F17C),
fastboot_unlock_execute_func(0x3A40F764), get_frp_lock_state_string(0x3A40F2AC), is_frp_open(0x3A415324),
get_bootinfo_lock_status(0x3A40F3CC), get_bootinfo_fblock_status(0x3A40F6C4)`。

---

## 3. 函数识别判据 + 全部实证地址

### 3.1 状态语义（两样本一致）
锁态编码：**0=locked，1=unlocked，2=relocked**。
- ELSP `certify_info` 结构（get_certify_info @0x3A41A734 返回全局 0x3A81F070 的指针）：
  `+0x104 fb_lock_stat, +0x108 user_lock_stat, +0x10C root_type, +0x110 check_sign_stat, +0x114 frp_stat`
- LIO 结构（全局指针 0x3A7D5248）：`+0x308 fb_lock_stat, +0x30C user_lock_stat, +0x310 root_type, +0x314 check_sign_stat, +0x318 frp_stat`

### 3.2 ELSP（经典路径，全部【实证】）
| 功能 | 函数 @ VA (size) | 关键内部点 |
|---|---|---|
| 锁状态初始化 | `fastboot_lock_stat_initial` @0x3A41B870 (0x148) | +0x2C bl get_securedebug_efuse_value 分支；+0x3C bl oeminfo_lock_stat_info → [certify+0x108] |
| **锁态判定（oeminfo HMAC 比对）** | `oeminfo_lock_stat_info` @0x3A41CAA4 (0x110) | common_oeminfo_read(0x5D,0x20) → userlock_hmac("ABABCDCDEF") memcmp→1；("EFEFABCDEF")→2；否则 0 |
| cmdline 锁态上报 | `creat_userlock_cmdline` @0x3A41C070 (0x138) | +0x28 ldr w1,[certify+0x108]；==1→"userlock=unlocked "；==2→"relocked"；else "locked" |
| 命令门控 | `fastboot_cmd_lock_state_chk` @0x3A41BE6C (0x12C) | 'oem unlock'/'flashing unlock' → tail bl check_frp_state @0x3A40FB30；返回 0=拒绝 |
| 解锁命令入口 | `usr_fastboot_unlock`(stub) @0x3A41CFAC → **`common_usr_fastboot_unlock` @0x3A41B0B8 (0x2FC)** | 见 3.3 |
| 回锁入口 | `usr_fastboot_relock`(stub) @0x3A41CFB0 → **`common_usr_fastboot_relock` @0x3A41B3B4 (0x36C)** | 额外要求 [certify+0x108]==1 且 oeminfo_root_type_info()!=1 |
| **密码校验** | `isec_userlock_check` @0x3A41CD68 (0x244) | w1 必须==0x10；common_oeminfo_read(0x1C,0x112)（OEMINFO_HWSB_AES_PWD）；[buf+0x10C]==1；memcpy 用户 16B key 到 +0x112；password_PBK_SHA256_RSA_check @0x3A4DBA70（参数 3,2）==0 通过 |
| **解锁写路径（oeminfo）** | `common_lock_stat_write` @0x3A41CBB4 (0x1B4) | state==1: userlock_hmac("ABABCDCDEF")→common_oeminfo_write(**0x5D**,0x20,buf) @0x3A41E020；state==2: "EFEFABCDEF"；返回负数=失败 |
| HMAC 计算 | `userlock_hmac.constprop.8` @0x3A41C7E4 (0x2C0) | secboot ops+0x60 派生密钥("USER")，crypto ops+0x20 HMAC(32B) → 写入 oeminfo item 0x5D，即 "user stat info" |
| misc 写复位 | `common_write_misc_resetmsg` @0x3A41D3F4 / `common_reboot_factory` @0x3A41D3FC | 解锁成功后写 misc + wipe/reboot |
| GUI 确认 | `common_display_lockchange_warning` @0x3A41E604 / `common_gui_main` @0x3A41E5A8 | 返回 0=继续(允许重启)，1=用户拒绝 |
| UFS 写保护 | `disable_oeminfo_write_protect` @0x3A41CFB4 (0x184)；`lock_state_locked` @0x3A41D138；`lock_state_unlocked` @0x3A41D294 | storage ops +0xB8 读 WP 状态，+0xA8/+0xB0 set/clear WP（oeminfo 0x1000000/0x800000 区及 0x3800000 备份区） |
| AVB 锁态 | `hisi_get_lock_state` @0x3A4CE378 (0xA0)；`hisi_avb_is_device_unlocked` @0x3A4CF240 (0xB8) | "fastboot_ctrl" ops[1] 取状态；*out==1 即 unlocked |

`common_usr_fastboot_unlock` 控制流（x0=响应结构, x1=密码 16B, w2=是否重启标志）：
```
[0x3A825484] 计数>4 → ret 0x55 (85)
x1==NULL → 'FAILdata parse fail'
[certify+0x108]==1 → 'FAILalready fastboot unlocked'      ← 0x3A41B120 b.eq
bl isec_userlock_check(x1,w1)                             ← 0x3A41B12C
cbz w0, +0x50 → 密码 OK 路径                              ← 0x3A41B134（else 计数+1 → 'FAILcheck password failed!'）
密码 OK：清计数 → bl common_display_lockchange_warning    ← 0x3A41B188
  ret==1 → 'FAILYou choose not to unlock the phone'
  否则：[certify+0x108]=1 → bl common_gui_main
        → bl common_write_misc_resetmsg（失败→'write misc reset factory failed'）
        → w0=1 → bl common_lock_stat_write(1)             ← 0x3A41B1BC（写 oeminfo 0x5D）
        → tbnz w0,#31 → 'FAILwrite oeminfo failed'（日志 'huawei_userlock: write oeminfo user stat info failed'）
        → (w24) bl common_reboot_factory → 响应 'OKAY', ret 0
```

### 3.3 LIO（经典路径被移除后的形态，全部【实证】）
| 功能 | 函数 @ VA (size) | 备注 |
|---|---|---|
| 锁状态初始化 | `fastboot_lock_stat_initial` @0x3A40FA20 (0x160) | **[certify+0x30C] 直接写 0（0x3A40FA64），不读 oeminfo HMAC**；root_type→+0x310；尾部 b set_secureos_rootstate @0x3A40F93C |
| cmdline 锁态上报 | `create_manufacture_secure_cmdline` @0x3A422780 (0x534) | +0x3FC/+0x3DC/+0x54 处 append 'userlock=unlocked/relocked/locked ' |
| 命令门控 | `fastboot_cmd_lock_state_chk` @0x3A40F17C (0x130) | 与 ELSP 同构：'oem unlock'/'flashing unlock'→check_frp_state @0x3A416538 |
| unlock 分发器 | `fastboot_unlock_execute_func` @0x3A40F764 (0xCC) | 表里**没有** unlock 项 → 对 'oem unlock' 返回 0xFF |
| **RSA 票据锁控** | `flash:slock` 处理器 @0x3A4209A0 (0x180，无名符号) | 计数器[0x3A7D6608]；要求载荷 0x100 字节；`data_RSA_public_decrypt` @0x3A4D533C；比对失败→'FAILpassword not match'；成功 @0x3A420CD8 置 [certify+0x308]=1 |
| 回锁族 | `cmd_hwdog_certify_relock` @0x3A420D10 / `cmd_hwdog_certify_set` @0x3A420EB8 | hwdog 认证回锁（'FAILfb lockstat not unlocked'） |
| check-rootinfo | `oem_check_root_info` @0x3A421864 (0x590) | 打印 INFOitem: userlock/fblock（ELSP 里是 stub→common_oem_check_root_info 0x3A41AAD8） |
| 状态读 | `oeminfo_root_type_info` @0x3A421DF4 (0xCC) | 读 oeminfo item 0x43；get_lock_state_string @0x3A40F408 与 ELSP 同构 |
| AVB | `hisi_get_lock_state` @0x3A4C91E4 / `hisi_avb_is_device_unlocked` @0x3A4CA0AC | 同 ELSP 结构 |

---

## 4. 补丁模板（ARM64 机器码，均已用 capstone 回编验证）

通用原子补丁：`NOP=D503201F`、`RET=D65F03C0`、`MOV W0,#0=52800000`、`MOV W0,#1=52800020`、
`MOV W1,#1=52800021`、`MOV W2,#1=52800022`、`STR W2,[X0]=B9000002`。
条件分支→无条件分支：`B target` = 0x14000000 | ((target−site)>>2 & 0x3FFFFFF)。

### 4.1 ELSP 经典路径补丁组（使 `fastboot oem unlock <任意16字节>` 走通真实写流程）
| # | 目的 | 站点 VA | 现指令(字) | 补丁(字) | 置信度 |
|---|---|---|---|---|---|
| E1 | 跳过密码校验（unlock） | 0x3A41B12C | 9400070F `bl isec_userlock_check` | **52800000** `mov w0,#0` | 实证 |
| E1' | 等效单指令（不改调用） | 0x3A41B134 | 34000280 `cbz w0,+0x50` | **14000014** `b 0x3A41B184` | 实证 |
| E2 | 跳过密码校验（relock） | 0x3A41B478 | 9400063C `bl isec_userlock_check` | **52800000** | 实证 |
| E2' | 等效单指令 | 0x3A41B480 | 34000600 `cbz w0,+0xC0` | **14000030** `b 0x3A41B540` | 实证 |
| E3 | 允许对已解锁机重复执行 | 0x3A41B120 | 540006A0 `b.eq 'already unlocked'` | **D503201F** `nop` | 实证 |
| E4 | 跳过 GUI 人机确认 | 0x3A41E604 | A9BD7BFD `stp x29,x30,[sp,#-0x30]!` | **52800000, D65F03C0** `mov w0,#0; ret`（占 2 指令，返回 0=同意） | 实证 |
| E5 | cmdline 永报 unlocked（非持久，伪装用） | 0x3A41C098 | B9410801 `ldr w1,[x0,#0x108]` | **52800021** `mov w1,#1` | 实证 |
| E6 | 强制 AVB/验证启动视作已解锁 | 0x3A4CE378 | A9BB7BFD `stp`（函数头） | **52800022, B9000002, 52800000, D65F03C0** `mov w2,#1; str w2,[x0]; mov w0,#0; ret` | 实证（布局推断 hisi_get_lock_state 契约） |

推荐最小组合：**E1+E2（或 E1'+E2'）+ E4** —— 保留真实 oeminfo 0x5D HMAC 写入与 misc 复位、reboot 流程，只是不再校验 16 字节密码；重启后 oeminfo_lock_stat_info 比对 HMAC 成功 → user_lock_stat=1 → cmdline/AVB 全链路自然报告 unlocked。E3 仅在需要重复解锁/救砖时加。E6 只影响 AVB 命令行（orange state），不持久化。

注意：E1 打掉密码校验后，`oem unlock` 仍要求 x1≠NULL 且走 'FAILdata parse fail' 分支的风险不存在（x1 为命令行解析出的 key 指针）；若 host 发送的 key 长度≠16，因校验已绕过无影响。

### 4.2 LIO 式路径补丁组（无 oem unlock 命令的版本）
| # | 目的 | 站点 VA | 现指令(字) | 补丁(字) | 置信度 |
|---|---|---|---|---|---|
| L1 | 初始化即置 user_lock_stat=1 | 0x3A40FA64 | B9030E7F `str wzr,[x19,#0x30c]`（此时 w1==1，见 0x3A40FA54 `mov w1,#1`） | **B9030E61** `str w1,[x19,#0x30c]` | 实证 |
| L2 | 绕过 flash:slock RSA 比对 | 0x3A420AC8 | 34001080 `cbz w0,+0x210`（memcmp 相等→成功） | **14000084** `b 0x3A420CD8` | 实证（成功路径已反汇编验证：置 [certify+0x308]=1 后 OKAY） |
| L3 | （按需）跳过 RSA 解密失败门 | 0x3A420A9C | 350006A0 `cbnz w0,+0xD4` | D503201F `nop` | 实证 |
| L4 | cmdline/状态上报 | 在 create_manufacture_secure_cmdline 内将锁态读取寄存器改 `mov wN,#1` | — | 需按 4G 版本现场定位 | 推断 |

LIO 路径本质：fastboot 自身不再持有"解锁"能力，只能伪装状态（L1/L4，非持久）或配合 RSA 票据（L2/L3，伪造 ticket 需私钥，不可行——但补丁后任意 256 字节载荷即可通过）。**持久解锁仍需 ELSP 式 oeminfo 写路径；若 4G 量产版两条路都没有，只能走 kernel/xloader 层方案。**

### 4.3 补丁落位验证方法
对每个站点：改前 dump 4 字节与本文"现指令(字)"比对；改后用 capstone 回编确认助记符与目标。
本目录 `m06_patch.py/m08_enc.py/m08b_enc.py` 即验证脚本（只读）。

---

## 5. ELSP ↔ LIO 偏移差与可移植性评估（m03_diff.txt 实测）

- **同名函数偏移差完全无规律**（-0xC7C ~ +0x6DBC，跨 -14 ~ +6 页）：ELSP 与 LIO 是不同配置的同一代码库编译，对象布局重排。**绝对偏移不可移植，锚点方法才可移植。**
- 同尺寸函数（check_unlock_misc_info 0x1d8/0x1d8、get_lock_state_string 0x148/0x148、do_write_oeminfo_item 0x1f8/0x1f8、hisi_avb_is_device_unlocked 0xb8/0xb8）结构同构但字节不同（重定位差异）——可作为"同一函数"的佐证（大小+字符串锚+调用形状三重匹配）。
- ELSP→LIO 结构性差异（也是量产化方向）：`oem unlock/reluck/flashing unlock/lock` 四命令表项被删；isec_userlock_check/common_lock_stat_write/userlock_hmac/oeminfo_lock_stat_info/creat_userlock_cmdline 五个函数整组消失（strings 同步消失，非 strip）；锁态初始化不再读 oeminfo 0x5D；新增 flash:slock + hwdog certify 家族（RSA 票据）；certify 结构从 +0x104 系变为 +0x308 系。

### 工程机 vs 量产锚点存活判据（4G TAS-AL00 预测）
| 锚点 | 工程机（ELSP/LIO） | 量产 4G 预测 | 依据 |
|---|---|---|---|
| `userlock=unlocked/relocked/locked ` | 两样本均有 | **大概率有** | cmdline 构建是内核启动必需 |
| `PHONE Locked/Unlocked/Relocked`、`oem get-bootinfo` | 两样本均有 | **大概率有** | get-bootinfo 属诊断功能 |
| `INFOitem: userlock/fblock` | 两样本均有 | **大概率有** | 状态查询 |
| `oem unlock` 字符串 + 命令表项 | ELSP 表有；LIO 表无（仅门控引用） | 表项**可能被删**（同 LIO） | 华为 2018 后关闭官方解锁 |
| `FAILcheck password failed!`、`userlock_hmac`、`ABABCDCDEF`、`OEMINFO_HWSB_AES_PWD` | 仅 ELSP | **很可能无**（同 LIO） | 经典密码路径整组裁撤 |
| `FAILpassword not match`、`FAILfb lockstat not unlocked` | 仅 LIO | 可能出现 | RSA 票据路径 |
| `hisi_avb: fail to get lock state`、`fastboot_ctrl` | 两样本均有 | **大概率有** | AVB 核心路径 |
| 内嵌符号表（nm 文本流） | ELSP/LIO 均有（`<addr> <bind> <type> <section>.<size> <name>.<next_addr>` 链式文本，ELSP 在 off≈0x41F000–0x49xxxx） | **量产大概率被裁** | strip 行为 |

**工程机文件自带符号表**这一事实意味着：任何拿到的新工程机明文可先搜 `\n000000003a` 系 nm 行直接重建全符号表（分钟级）；量产版才需要走纯锚点流程。

---

## 6. 4G dump 标准作业程序（SOP）

1. `python m02_analyze.py`（改 FILES 路径与字符串 VA 表）→ 产出 funcs/xref/callers/tables 四件套；
2. 按 1.1/1.2/1.3 锚点命中情况判分支（ELSP 式 / LIO 式 / 更老）；
3. 命令表回溯：搜锚点字符串 VA 的 QWORD 指针 → +8 取 handler → 解 stub B → 拿实函数；
4. 反汇编实函数，对照第 3 节判据逐条核对（门控/密码/写路径三段式结构）；
5. 套第 4 节补丁模板：先在 IDA/二进制副本上打，再 capstone 回编验证；
6. 全流程只读原固件；补丁写到副本，刷写由既有 4G 刷写链路（readback/z_route 系列）执行。

## 附录：本目录脚本与产物
| 文件 | 作用 |
|---|---|
| m02_analyze.py | 符号表解析+目标函数带注解反汇编+字符串 xref+BL 调用图+命令表（m02_*_funcs/xref/callers/tables.txt） |
| m03_follow.py | 运行时表指针跟随（m03_tables2.txt）、ELSP↔LIO 偏移差（m03_diff.txt）、内嵌符号表样本（m03_embedsym.txt） |
| m04_lio.py / m05_lioptr.py | LIO 顶层命令名数组与 ops 结构指针追踪（m04_lio_tables.txt / m05_lio_dispatch.txt） |
| m06_patch.py / m08_enc.py / m08b_enc.py | 补丁站点现场指令 dump 与全部替换字码 capstone 回编验证 |
| m07_embed.py | 内嵌符号表格式解码（m07_embedsym.txt） |

（ELSP 符号全表：`kirin9905Gexploit 上游仓库 IDA/990els.txt`；LIO：`990lio.txt`，nm 文本格式，本分析的事实基准。）
