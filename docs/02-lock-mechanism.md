# 华为双层锁机制分析(基于 TAS-AL00 / Kirin 990 / EMUI 11 实测逆向)

## 一、双层锁结构

| 锁 | 显示命令 | 存储位置 | 管控范围 |
|---|---|---|---|
| **FB Lock** | `oem lock-state info` → FB LockState | `oeminfo_rdmode_info()` 读 NV 项, 成功=1(UNLOCKED), 失败=0(LOCKED) | **所有分区**校验+刷写权限 |
| **USER Lock** | `oem lock-state info` → USER LockState | `oeminfo_lock_stat_info()` 读 NV 0x5D 项, 1=UNLOCKED | 仅 boot/system/recovery/recovery_ramdisk/kernel |

- 两套存储互相独立:FBLOCK NVE 项(970+)与 FB Lock **脱钩**(写 00 无效)
- `oem get-bootinfo` 显示 = 独立的 bootinfo 标记, 与 lock-state 机制不同步

## 二、关键函数地址(镜像基址 0x3A400000, 设备加载基址 0x1A400000)

| 函数 | VA | 偏移 | 作用 |
|---|---|---|---|
| fastboot_lock_stat_initial | 0x3a413594 | 0x13594 | 锁状态初始化(EMUI9.1.1+ 硬编码 USER=LOCK) |
| oeminfo_lock_stat_info | 0x3a426a28 | 0x26A28 | 读 NV 0x5D = USER Lock 真值 |
| oeminfo_rdmode_info | 0x3a4274f0 | 0x274F0 | 读 NV 0x82 = FB Lock 真值(读失败=LOCKED) |
| get_bootinfo_lock_status | 0x3a412f40 | 0x12F40 | bootinfo 显示 getter |
| get_bootinfo_fblock_status | 0x3a413238 | 0x13238 | fblock 状态 getter |
| fastboot_cmd_lock_state_chk | 0x3a412cf0 | 0x12CF0 | 命令权限门 |
| usr_fastboot_unlock | 0x3a42534c | 0x2534C | oem unlock 处理 |
| check_boot_mode | 0x3a405460 | 0x05460 | 重启原因判定(>6=错误) |
| boot_kernel | 0x3a4b4d5c | 0x0B4D5C | 温启动内核(cmdline→copy_dts→chipid→跳转) |
| cmd_hwdog_certify_put | 0x3a424b88 | 0x24B88 | slock 验证写入(TLV 循环) |
| data_RSA_public_decrypt | 0x3a4df518 | 0x09F518 | slock RSA4096 验签 |

## 三、补丁字节(ARM64)

```
mov w0,#0  = 00008052 c0035fd6 (ret 0)
mov w0,#1  = 20008052 c0035fd6 (ret 1)
NOP        = 1f2003d5
```

写回类(基础设施): P1 isec 原语 / Pgate 命令门 / P2 certify 门 / WP+P11wp 写保护 / P12fw / P5b+P13avb
检测类(勿永久): P7a bootinfo 显示 / P8 fblock 显示 / P9 verifyboot / P10 secboot / P14fb rdmode→1 / P5cbm 强普通启动 / P16dis 显示门

## 四、实测状态(2026-09)

- USER Lock: **真解锁持久**(原装 fastboot 读出 UNLOCKED, oem unlock 认账 already unlocked)
- FB Lock: 显示 LOCKED(原装读数), 会话内 P14fb 强制 UNLOCKED
  - 永久化路线: 直接调用写入函数(绕过 RSA/TLV 校验)或 slock TLV 正确构造
- bootinfo 显示 locked = 独立标记与锁机制不同步(两套存储)

## 五、注意事项

- FBLOCK NVE 项写 00 在 Kirin 970+ 对 FB Lock **无效**
- 检测类补丁不可永久固化(每次引导重算), 只在 staged 会话内有效
- 网上"E180 系"或"10.0.0.135 系"完整包与此设备版本(C00E167R5P3)**不匹配, 严禁混刷**
