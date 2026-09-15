# mate30-bl-unlock

华为 **Mate30（麒麟 990 4G，TAS-AL00）** bootloader（BL）解锁方案与配套工具集。

## 项目成果总览

- ✅ BootROM 下载模式 → 任意代码执行（USB CDC 协议 + xloader/UCE 链）
- ✅ staged fastboot 任意读写原语（补丁原语 + stub 执行）
- ✅ xloader / fastboot 明文回读（192KB ELF / 4.67MB 全量）
- ✅ 双层锁机制完整逆向（FB Lock / USER Lock 语义与存储位置）
- ✅ 双锁解锁（原装 fastboot 亲口读出双 UNLOCKED）
- ✅ BL2 日志捕获通道（`oem memory bl2`）
- ⏳ 引导分流标志定位（进行中）
- ⏳ 鸿蒙 4.2 OTA 获取（路径已定：本机 OTA 递进）

> [!CAUTION]
> **本项目全部代码、分析与文档均由 AI（AI 助手）生成，未经人工逐行审核。**
> 作者**不对生成代码的质量、正确性或安全性作任何担保**；因生成代码缺陷导致的任何设备损坏、
> 变砖、数据丢失、信息安全事件或其他一切后果，作者**概不负责**。使用前请自行验证每一条指令、
> 每一个字节。若你据此复现，**请逐项仔细核对，避免被误导**。

> [!WARNING]
> 本仓库内容是个人在自有设备上的探索与复现记录，作者并非职业安全研究员。解锁会清数据、
> 可能变砖、失去官方安全更新与银行/政务类应用兼容性。仅限用于**自己拥有的设备**，
> 严禁用于他人设备或任何违法用途；一切操作后果自负。

---

## 1. 漏洞背景

麒麟 990 的 bootrom 利用主要基于 TASZK 团队（Black Hat USA 2021）与盘古团队公开的 "checkmate30" 漏洞链，但公开的实操细节有限。本仓库在 990 **4G**（TAS-AL00）上完成了从明文回读到解 BL 的工程化落地，相关原文：

- TASZK 团队白皮书：[How To Tame Your Unicorn (Black Hat USA 2021)](https://i.blackhat.com/USA21/Wednesday-Handouts/US-21-Komaromy-How-To-Tame-Your-Unicorn-wp.pdf) —— 海思启动链（BootROM→xloader→TEE）安全分析的理论源头
- 盘古团队（Checkmate Mate30）：[panguteam/checkm30](https://github.com/panguteam/checkm30)（MOSEC 2021 演讲配套，上游已失效，可搜索存档）
- 麒麟 990 **5G** 的复现文档：[XingChenRS/kirin9905Gexploit](https://github.com/XingChenRS/kirin9905Gexploit)（MIT）—— 本仓库的方法论与符号表大量参考该项目

## 2. 固件加载地址（Kirin 990 4G 实证）

| 固件 | 阶段 | 存放/运行地址 | 说明 |
|---|---|---|---|
| XLOADER | BootROM 下载 | `0x00022000` (SRAM) | 解密前后地址一致 |
| FASTBOOT | xloader 下载期暂存 | `0x1A400000` (DDR) | 加密态暂存 |
| FASTBOOT | 主 CPU 启动后（bootloader 态） | `0x3A400000` (DDR) | 实际运行地址（明文在此） |
| BL2 | xloader 加载 | `0x1E400000` (DDR) | 预校验新阶段 |
| UCE | xloader 加载 | `0x60000000` (DDR) | 负责 DDR 初始化 |

与 5G 版一致：除 bootrom 外所有固件加密存储，解密密钥在 EFUSE（每片唯一），仅 TEE 可直接访问；解密阶段不可绕过——明文固件直接上机会因"解密不一致"而失败。所以正确姿势是：**喂官方加密包让设备自己解密，再想办法把明文读出来**。

## 3. 解BL思路

```
[BootROM] FRESH 会话(07)
   │  null 载荷（解密后）@0x22000 + 线缆舞步 (TP4009 OFF 3s ON)
   ▼
[BootROM] 喂官方 BD 包 sec_usb_xloader.img → 设备端解密器原位解密运行
   │  ★利用点1: BootROM 下载协议 HEAD 帧可重发 → 任意地址写 (bug2_write)
   ▼
[SRAM 注入] 回调 payload @0x5C400（CD 应答劫持 + 分发器 + 向量表 + 休眠返回链喷涂）
   │  ★利用点2: xloader 下载协议 HEAD 帧 ADDRESS 不校验 → 任意读
   │  触发: 纯静默 150s x2（xloader 版）/ 关串口 3s（fastboot 版）
   ▼
[收割] CD 应答按 4B/次送回明文
   ├── readback_xloader.py  → xloader 明文 (192KB ELF)
   └── readback_fastboot.py → fastboot 明文 (4.67MB, DDR @0x3A400000)
   ▼
[解BL] 在明文 fastboot 中定位锁函数 → 运行期补丁（7 处）→ BL2 触发启动
        → 设备重枚举为 fastboot → oem unlock 任意码 → 解锁完成
```

- **漏洞链**：docs/05（任意读定案）、docs/06（BootROM/xloader 逆向全记录）
- **锁机制**：FB Lock（`rdmode` NV）+ USER Lock（NV 0x5D）双层锁，docs/02
- **补丁方案**：P1 任意码解锁 + 命令门/logo/AVB/certify 放行共 7 处补丁，docs/03
- **锁函数定位方法论**：无符号明文中锚点字符串 → xref → 补丁模板，docs/04

> 以上链路已在自有设备实测走通：原装 fastboot 亲口读出 FB Lock / USER Lock 双 UNLOCKED。

## 核心发现（摘要）

1. **双层锁**：FB Lock（深层，`rdmode` NV 项判定）+ USER Lock（oeminfo bootinfo NV 项）。
   Kirin 970+ 后 FB Lock 与 NVE FBLOCK 项脱钩，走 slock RSA 机制。
2. **补丁体系**：fastboot 为 ARM64，偏移补丁（写回类：命令门/写保护/AVB；检测类：锁显示/rdmode）。
3. **flash 任意读**：`upload_storage:<十进制start>:<十进制len>`（4 对齐，分区上下文前置）。
4. **always-on 残留**：调试会话残留状态可导致引导分流；完全断电（电池耗尽）可清除。
5. 详细见 `docs/`。

## 4. 仓库结构与使用

```
├── docs/                       方案与逆向文档（6 篇，见上文编号）
├── tools/                      ★可直接使用的脚本
│   ├── console_ui.py                    控制台 UI 组件（零依赖）
│   ├── config.example.ini               配置样例 → 复制为 config.ini 填写
│   ├── readback_xloader.py              xloader 明文回读（交互式进度）
│   └── readback_fastboot.py             fastboot 明文回读（4.67MB 整取，交互式进度）
├── research/                   底层研究材料
│   ├── xloader_send.py                  xloader 下载协议库（XMODEM 帧/CRC/进度回调）
│   ├── PROTOCOL.md                      xloader 下载协议完整逆向记录
│   ├── ar_read_poc.py                   任意读 PoC（probe/selftest/arm/scan/dump/restore）
│   └── disasm/                          会话期逆向脚本存档（BootROM 扫描/锁函数反汇编/符号检索）
└── probes/                     诊断小工具（fb_raw / backup_dd / port_listen / scan_dumps）
    │                                    + parse_bl2log（BL2 日志解析，oem memory bl2 通道）
    │                                    + pollute_diag（调试会话残留/引导分流诊断）
```

环境：Windows 10+、Python 3.10+、`pip install pyserial keystone-engine`。

```bash
cd tools
copy config.example.ini config.ini      # 填写路径后保存

python readback_xloader.py              # xloader 明文 → XLOADER_BD_PLAIN.bin
python readback_fastboot.py             # fastboot 明文 → FASTBOOT_PLAIN.bin
python ..\research\ar_read_poc.py       # 任意读 PoC（无参数看帮助）
```

两个回读工具带**实时进度反馈**：阶段横幅、进度条（速率）、静默等待倒计时、逐步 OK/FAIL
判定与蜂鸣提示；失败自动重试（默认最多 40 轮），Ctrl+C 随时安全中断。

## 5. 自备组件

| 组件 | 用途 | 获取 |
|---|---|---|
| 官方 BD 工程固件包（TAS-AL00，BD 1.0.0.33） | 提供 `sec_usb_xloader.img` / `sec_usb_xloader2.img` / `sec_fastboot.img` | [needrom: Huawei Mate 30 Taurus-AL00B BD](https://www.needrom.com/download/huawei-mate-30-taurus-al00b-bd/) |
| null 载荷解密模块（`kirin_loader.py`） | 解出进入下载链所需的 null 载荷 | 自备组件，不随本仓库分发（运行时经 `config.ini` 指定目录） |

## 6. 已验证范围（重要）

- 机型: **华为 Mate30 4G（TAS-AL00）**，系统版本 **10.1.0.132**，BD 包 **1.0.0.33**，鸿蒙/EMUI 引导链
- **本仓库全部脚本仅在上述这一台设备、这一个系统版本上测试过。** 其他机型、其他系统版本、
  其他 BD 包版本均未测试：payload 地址表（0x5C400 系列）、补丁偏移、DDR 驻留地址**都可能不同**，
  需要用 docs/04 的方法论自行核对，直接照跑大概率失败
- 回读工具只写 SRAM/DDR 运行内存、不碰设备持久存储；但任何地址错误仍可能导致设备当日无法开机
  （拔电重进下载模式可恢复），务必先看懂再跑

## 7. 风险提示

1. **AI 生成风险**：全部代码由 AI 生成、未经人工逐行审核，可能存在错误甚至危险操作；
   作者不对生成代码质量导致的任何损坏负责（见顶部声明）。
2. **物理操作**：设备需进入 USB 下载模式（VID 0x12D1/PID 0x3609 串口）；部分步骤需要断开
   主板测试点（TP4009）——0.1mm 间距，操作不当可能损坏 PCB。
3. **变砖风险**：补丁写入引导链后由 BL2 触发执行，任何地址/字节错误都可能导致无法开机。
   本仓库工具的失败模式设计为"不写持久状态"，但仍请先做好分区备份（probes/backup_dd.py）。
4. **数据风险**：解锁会触发出厂重置类行为，请提前备份全部数据并记录锁屏密码/账号凭证。
5. **法律风险**：固件解密与修改可能违反《计算机软件保护条例》等法规；解锁可能违反所在地区
   保修条款。仅限技术研究与自有设备。
6. **隐私**：本仓库不含任何密钥、token、固件、序列号与 dump 文件。提 issue 时同样不要贴
   含序列号的日志或你的 config.ini。

## 8. 参考资料与致谢

| 材料 | 作者/来源 | 对本项目的意义 |
|---|---|---|
| [How To Tame Your Unicorn](https://i.blackhat.com/USA21/Wednesday-Handouts/US-21-Komaromy-How-To-Tame-Your-Unicorn-wp.pdf) | TASZK, Black Hat USA 2021 | 海思启动链与 TEE 解密机制的理论基础（白皮书） |
| [checkm30](https://github.com/panguteam/checkm30)（MOSEC 2021） | 盘古团队 | Checkmate Mate30 漏洞链公开演讲（PPT/视频，上游已失效可搜存档） |
| [kirin9905Gexploit](https://github.com/XingChenRS/kirin9905Gexploit)（MIT） | XingChenRS | 990 5G 复现文档、工程机 fastboot 符号表（ELSP/LIO）、payload 思路 |
| [Kirin-Tool](https://kirintool.cfd)（BUSL 1.1） | Kethily Daniel & NDXCode | 参考了其中的部分思路。注意：其方案面向麒麟 990 **5G**，与本项目的 4G 设备不通用 |

## License

MIT — 见 [LICENSE](LICENSE)
