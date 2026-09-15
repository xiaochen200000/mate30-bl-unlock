# TAS-AL00 下载模式协议文档(最终版)
# 整理自项目全程逆向,与工具箱配套

## 一、串口链路(下载模式 CD 协议)
- 端口: VID_12D1 PID_3609 (HUAWEI USB COM 1.0), 波特率无关(USB CDC)
- 会话建立: V.session_start(port) → FRESH 回 0x07, 暖态回 0xAA
- head 帧: FE 00 FF ft(1B) len(4B BE) addr(4B BE) + crc16(2B BE)
  - ft=1: 写入地址请求(head(addr, n))
- data 帧: DA seq(1B) ~seq(1B) + payload
- wr_ack: 发 head+data → 等单字节 ACK
- cd_read: 写 cursor 地址(写入 4B 到 cursor 全局) → 读回 n 字节
- 读/写原语: arm() 安装 stub 代码(三段补丁 A/B/C)后, cursor 指向任意地址即可读写
- cursor 全局地址: M['cursor'](NEW 模型=镜像基址+0x41170 附近, Z.probe_model 自动判)

## 二、引导链(staged fastboot 拉起)
1. FRESH 07 → upload xloader → 0x22000 (tail 触发接管)
2. find_xloader_session → 新会话
3. upload UCE → 0x60000000 (SRAM)
4. 等 10s → upload fb(fastboot 容器) → 0x1A400000
5. TEE 解密等 20s → probe_model(NEW/OLD) → selftest → arm(装读写 stub)
6. 打补丁(13-16 个, 偏移=镜像内地址) → 读回验证
7. upload BL2 → 0x1E400000 (tail 触发) → BL2 接管 → fastboot USB 枚举

## 三、补丁表(当前最终版 9-16 个)
核心(写回基础设施):
  P1    0x26DBC  isec 原语门        00008052c0035fd6
  Pgate 0x12CF0  命令门(lock_state_chk) 20008052c0035fd6
  P2    0x25100  certify 会话门     1f2003d5 (NOP)
  WP    0x99BF4  写保护             00088012c0035fd6
  P11wp 0xA54F8  写保护2            00088012c0035fd6
  P12fw 0xB6D8   flash write        00008052c0035fd6
检测类(按需, 默认撤除):
  P7a   0x12F40  get_bootinfo_lock_status 显示
  P8    0x13238  get_bootinfo_fblock_status 显示
  P9    0x136F8  verifyboot 锁状态
  P10   0x1385C  secboot 锁状态
  P14fb 0x274F0  rdmode→1 (FB=UNLOCKED 显示)
  P5cbm 0x5490   check_boot_mode 强普通启动
  P16dis 0x91FC  显示门 NOP

## 四、fastboot 命令(补丁后可用)
- flash <分区> <文件>       写分区(写保护已补)
- erase <分区>              擦分区(userdata 擦除连带 oeminfo crypt info 清除)
- oem lock-state info       锁状态显示
- oem get-bootinfo          bootinfo 显示
- oem hwdog certify set N   FB 锁 NVE 写(门=P14fb)
- oem hwdog certify enc begin  slock 挑战(FBLOCK+48hex)
- flash slock <文件>        slock 验证写入(TLV 循环, 需正确构造)
- upload_storage:<十进制start>:<十进制len>  flash 读回(4对齐, 十进制!)
  ※ 偏移 0 处=真实空区(全零非假读); hex 串参数=解析垃圾必失败
- oem memory <name> <文件>  RAM 区转储(bl2/bl31/pstore/kerneldump/bbox/lpmcu_image)

## 五、锁状态语义
- USER Lock: oeminfo NV 真值(0x5D 项), 1=UNLOCKED(持久, 当前已解锁)
- FB LockState: oeminfo_rdmode_info() 读 NV 0x82 项, 成功→1=UNLOCKED, 失败→0=LOCKED
  当前显示 LOCKED 的原因=0x82 项读失败(待修); P14fb 补丁=会话内强制 1
- FBLOCK NVE 项: 970+ 已与 FB Lock 脱钩(写 00 无效)

## 六、FB Lock 永久解锁路线(定案)
- 直接调用写入函数: staged fastboot stub 执行原语 → BL 调用
  候选: set_control_flag_to_oeminfo@0x3a41fe60 / certify_put 成功路径 ops[0]
- slock 三针备选: P17a=0x424C84 NOP / P17b=0x424C94 NOP / P17c=0x424CA8 mov w0,#0
  ※ certify_put 成功/失败路径=TLV 流解析循环, 任意数据会死循环, 需正确 TLV 构造

## 七、已知不可读区
- 0x80000000+ (BootROM 判定寄存器): xloader 总线搁浅, 物理不可读
- upload_storage hex 参数: 解析垃圾必 FAIL(只认十进制)
