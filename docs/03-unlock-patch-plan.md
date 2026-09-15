# 解锁补丁计划（fastboot 明文已到手）

日期：2026-09-10
依据：`ARDUMP_1A400000.bin`（= `FASTBOOT_4G_PLAIN_READBACK_OK.bin`，4,669,440 B，
基址 **0x3A400000**，镜像内嵌完整 nm 符号表 @0x3E7000+，6436 个函数全有名字）
备份：`BACKUP_20260910.zip`（31 文件 + 记忆目录 + MANIFEST.sha256）

## 0. 需求（已核对）

1. FB 锁 + user 锁双解
2. 改解锁机制：`oem unlock <任意码>` 走**真实解锁流程**（状态回写持久化），不是只骗过校验
3. 补丁 5（启动模式验证）+ 补丁 6（logo 加载）→ 打完能直接进系统
4. 收尾关闭实验留下的调试项（不短接也能进下载模式等）

## 1. 锁机制全图（符号表实证）

```
命令表 @0x3B2EE0:  oem unlock      -> usr_fastboot_unlock @0x2534C (0x374)
                   flashing unlock -> 同一处理函数 0x2534C          ★一个补丁两命令通用
                   oem relock      -> usr_fastboot_relock @0x256C0
                   flashing lock   -> 同 0x256C0
                   oem frp-erase   -> 0x25A98   oem frp-unlock -> 0x25BE0

usr_fastboot_unlock 流程:
  [x19+4] 计数器 > 4        -> 回 0x55（防爆破）
  [state+0x30C] == 1        -> 已解锁提示分支 0x254BC
  bl isec_userlock_check    -> ★解锁码校验（0x26DBC, 0x2AC）
     输入码必须恰好 16 字节
     TEE 调用 (cmd 0x1C/0x112) -> 结果在 0x144 缓冲 +0x10C（==1 通过）
     通过后: 记录[+0x112]=码,+0x122=len(16) -> password_PBK_SHA256_RSA_check(记录,3,2)
  校验返回 0                -> blr [x24+0x28]   ★无参回调 = 真实解锁执行器
  （回调不需要输入码 => 改校验不影响回写所用密钥material）
```

## 2. 补丁集

### P1 ★核心：任意码解锁（机制级，回写保持原厂）
- 目标：`isec_userlock_check` @ **0x26DBC**（文件偏移；DDR 运行地址 0x1A400000+0x26DBC）
- 补丁：`00 00 80 52  C0 03 5F D6`  = `mov w0,#0; ret`（与 ELSP 时代 00008052/c0035fd6 同款）
- 覆盖：oem unlock / flashing unlock（同一 handler）；oem relock 的 0x257A4 调用点也走它
- 原理：跳过整段 RSA/TEE 校验 → handler 直接进无参真回调 → oeminfo_lock_stat_write /
  userlock_hmac / fastboot_derive_key 全部原厂执行，锁状态以设备自身密钥回写持久化
- 备选 B（若回调依赖密码记录）：在 0x26E2C-0x26E34 强制 verdict==1 分支
  （`ldrh w20,[x19,#0x10C]; cmp w20,#1; b.eq 0x26F14` → 无条件跳 0x26F14），
  让"码复制+记录存储"照跑——但记录里是错码，需运行时观察 0x3A4E1CE8 校验是否放行

### P5 启动模式验证
- 锚点：`check_boot_mode` @0x5460 (0x150)；`load_kernel` @0xB40D0；
  `load_kernel: bootmode err` 字符串引用 @0xB3C18（符号表未覆盖的静态函数）；
  `create_verify_mode_cmdline` 引用簇 @0x372EC/0x375CC/0x37774/0x37828；
  `change_system_boot_mode` @0xB24A8、`get_boot_mode` @0xB3440、`reset_boot_mode` @0xB3434
- 具体补丁字节待运行时观察失败点后定（先跑一次看卡在哪）

### P6 logo 加载
- 锚点：`lcd_logo_checksum_check` @0x88118 (0x3F0)（logo 校验和）、
  `logo_init` @0x5AB48、`hisi_prepare_logo` @0x5B75C、`hisi_display_no_logo` @0x5B134、
  `hisi_display_logo` @0x53D84
- 同 P5，运行时确认失败点后定补丁

### P7 调试项清理（收尾做）
- `get_securedebug_efuse_value` @0x276D8 / `get_securedebug_efuse_value_for_compatible` @0xE5C18
- secdbg 全套：`verify_secdbg_img` @0x10D2EC、`write/restore/erase/save_secdbg_img_*` @0x50CA8C+
- "不短接进下载模式"的根因（ver_mode / secdbg 标志）待运行时确认

## 3. 运行时流程（下一场实验）

```
1. 现有链到 xloader 会话（z_run_read.py 前半）
2. staging: UCE@0x60000000 + fastboot@0x1A400000（加密容器，TEE 解密进 DDR）
3. z_ar_read 三阶段 arm（已实证）
4. ★用任意写给 DDR 里的 fastboot 打 P1 补丁（0x1A400000+0x26DBC，8 字节）
5. 触发启动：补 stage BL2@0x1E400000（v145 路线）→ 观察交接/自启；
   若不自启，在 xloader 明文/UCE 里找 boot 触发（ED type=2? 独立命令?）
6. fastboot 起来后: fastboot oem unlock <任意16字节> → 观察回执与状态
7. getvar / 重启验证持久化；再定 P5/P6/P7 补丁
```

## 4. 已知风险

- 0x3A400000 读=挂设备（两次实证）；其余 DDR 候选未测
- BL2 是否重新校验 fastboot（决定 P1 打在 DDR 是否够）——运行时确认
- xloader 侧对 fastboot 的校验（需求 3）：xloader 明文里 "xloader3 verify fail"、
  "BOOTMAGICNUMBER!" 相关路径，同样可用任意写运行时 NOP

## 5. ★新增需求（09-10 第二轮核对）

### R4 基带/字库全备份 —— 原厂命令现成！
BD 工程 fastboot 内置工程命令（命令表实证，无需自研）：
- **`upload_storage:`** -> usbcmd_upload_storage_func @0xADC4 —— **分区/存储读回**（表内注册两处）
- `upload_memory:` -> usbcmd_upload_memory_func @0xABA8 —— 内存读回
- `dump:` -> usbcmd_dump_func @0xA790
- 主机侧：发命令后用 fastboot 协议 upload 阶段（`fastboot get_staged`）收数据
GPT 分区表（ptable.img，79 分区）备份清单（★=必须）：
- 基带族：modem_secure(8.5M)/nvme(5M)/modemnvm_factory(16M)/modemnvm_backup(16M)/
  modemnvm_img(34M)/modemnvm_update(16M)/modemnvm_cust(16M)/modem_patch_nv(4M)/
  modem_fw(56M)/modem_driver(20M)/hieps/hisee_fs
- 锁状态族：oeminfo(96M!)/frp(0.5M)/secure_storage(32M)
- 引导族：bl2/fastboot/vector/vrl/vrl_backup/kernel/vbmeta×5/recovery_vbmeta/erecovery_vbmeta/
  recovery_ramdisk+vendor/erecovery_*/splash2/dts/dto/trustfirmware/teeos/hisee_img/hhee/fw_lpm3
- 顺序：**先备份后解锁**；备份动作本身不动任何数据，纯读

### R5 刷写解除限制（酷安情报：解锁后无法刷写/改内核开不了机）
- 写保护链（"无法刷写"首嫌）：`check_secure_protect_lock_status` @0x99BF4、
  `verify_partitions_write_protectable` @0x99688、`storage_get/set_config_descriptor_lock`
  @0xA5A2C/0xA5B24、`ufs_rpmb_secure_write_protect_config_block_read/write` @0x14F78C/0x14F9A4
- AVB 链（"改内核开不了机"）：`avb_verifyboot` @0xB1390、`hisi_avb_verifyboot` @0xD4B08、
  `hisi_avb_is_device_unlocked` @0xD452C、`load_and_verify_vbmeta` @0x1E8518、
  `verify_image` @0xB3450、`verify_image_locked`、`save_verify_boot_state` @0xAC178、
  `get_lock_status_for_verifyboot` @0x136F8
- 策略：解锁状态回写成功后，这些多半自然放行（is_device_unlocked=true）；
  仍拦的再逐个 NOP。刷写命令本体：`flash:` 现代处理 + `legacy_usbcmd_flash_func` @0xBC6C、
  `ultraflash:`、`usbcmd_erase_func` @0xCD44
- fastbootd：若 bootloader 层刷写受限，Android 侧 fastbootd 是 userspace 方案；
  但先试 BD 工程 fastboot 的 flash:/ultraflash:，工程版大概率无消费级限制

### R6 .su 即 root（盘古式，非必备）
- 思路：我们控制 fastboot 代码（DDR 补丁），.su 文件格式**由我们自定义**：
  给 `flash:` 处理函数加 8-16 字节魔数头判断（命中即把载荷当 ARM64 代码执行或
  写入 + 设置属性），载荷内容=写 /system/xbin/su + magiskinit 之类
- 好处：不用刷改过的 boot 镜像，避免"改内核开不了机"问题；刷一次即可
- 实现时机：fastboot 能跑、DDR 补丁流程稳定之后再做（需要先摸清 flash: 的写入路径）

## 6. 执行顺序（更新）

```
0. （原样）链到 xloader 会话 → staging → arm
1. ★boot 触发实验：补 BL2@0x1E400000 / 找触发命令 → fastboot 起来
2. ★R4 备份：upload_storage: 把 ★清单 逐个读回（get_staged 落盘，存 BACKUP 分区目录）
3. P1 打 DDR → oem unlock <任意16B> → 验证回执 + getvar unlock 状态
4. 重启验证持久化 → 不行则查 BL2/xloader 侧状态校验
5. R5：试 flash:（小分区）→ 被拦则逐个 NOP 写保护/AVB
6. P5/P6：观察进系统卡点 → 定补丁字节
7. R7（可选）.su 载荷 → root
8. P7 调试清理（securedebug/secdbg/ver_mode）→ 收尾
```
