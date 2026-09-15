# mate30-bl-unlock

华为 **Mate30（麒麟 990 4G，Taurus-AL00B）** bootloader（BL）解锁方案与配套工具集。

> [!WARNING]
> 本仓库内容是**个人在自有设备上的探索与复现记录**，部分操作借助了第三方工具或 AI。作者并非职业安全研究员，内容可能存在未经验证的假设与疏漏。若你打算据此复现，**请逐项仔细核对，避免被误导**。

> [!WARNING]
> 解锁会清数据、可能变砖、失去官方安全更新与银行/政务类应用兼容性。一切操作后果自负。仅限用于**自己拥有的设备**，严禁用于他人设备或违法用途。

---

## 1. 漏洞背景

麒麟 990 的 bootrom 利用主要基于 TASZK 团队（Black Hat USA 2021）与盘古团队公开的 "checkmate30" 漏洞链，但公开的实操细节有限。本仓库在 990 **4G**（Taurus）上完成了从明文回读到解 BL 的工程化落地，相关原文：

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
   │  null.ktl 解密产物 @0x22000 + 线缆舞步 (TP4009 OFF 3s ON)
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
│   └── ar_read_poc.py                   任意读 PoC（probe/selftest/arm/scan/dump/restore）
└── probes/                     诊断小工具（fb_raw / backup_dd / port_listen / scan_dumps）
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
| 官方 BD 工程固件包（Taurus-AL00B BD 1.0.0.33） | 提供 `sec_usb_xloader.img` / `sec_usb_xloader2.img` / `sec_fastboot.img` | [needrom: Huawei Mate 30 Taurus-AL00B BD](https://www.needrom.com/download/huawei-mate-30-taurus-al00b-bd/) |
| `kirin_loader.py` + `null.ktl` | null 载荷解密（`dtl()`） | 见下方说明 |

**为什么 ktl 密钥与解密模块不入仓库**：`null.ktl` 的解密依赖 Kirin-Tool 内嵌的密钥材料，
那是**Kirin-Tool 作者自己的密钥**，我们放上来既没有使用价值，也不符合其许可与作者意愿。
Kirin-Tool 本体为 **BUSL 1.1** 许可（source-available，非开源），禁止随意再分发其代码与衍生作品。
请自行从官方渠道获取该工具（[kirintool.cfd](https://kirintool.cfd)），自备解密模块，仓库只提供调用接口约定
（`dtl()` + `LOADER_DIR` 下的 `null.ktl`）。同理，官方固件有版权，本仓库只给链接不放假包。

## 6. 风险提示

1. **物理操作**：设备需进入 USB 下载模式（VID 0x12D1/PID 0x3609 串口）；部分步骤需要断开
   主板测试点（TP4009）——0.1mm 间距，操作不当可能损坏 PCB。
2. **变砖风险**：补丁写入引导链后由 BL2 触发执行，任何地址/字节错误都可能导致无法开机。
   本仓库工具的失败模式设计为"不写持久状态"，但仍请先做好分区备份（probes/backup_dd.py）。
3. **法律风险**：固件解密与修改可能违反《计算机软件保护条例》等法规；解锁可能违反所在地区
   保修条款。仅限技术研究与自有设备。
4. **隐私**：本仓库不含任何密钥、token、固件、序列号与 dump 文件。提 issue 时同样不要贴
   含序列号的日志或你的 config.ini。

## 7. 参考资料与致谢

| 材料 | 作者/来源 | 对本项目的意义 |
|---|---|---|
| [How To Tame Your Unicorn](https://i.blackhat.com/USA21/Wednesday-Handouts/US-21-Komaromy-How-To-Tame-Your-Unicorn-wp.pdf) | TASZK, Black Hat USA 2021 | 海思启动链与 TEE 解密机制的理论基础（白皮书） |
| [checkm30](https://github.com/panguteam/checkm30)（MOSEC 2021） | 盘古团队 | Checkmate Mate30 漏洞链公开演讲（PPT/视频，上游已失效可搜存档） |
| [kirin9905Gexploit](https://github.com/XingChenRS/kirin9905Gexploit)（MIT） | XingChenRS | 990 5G 复现文档、工程机 fastboot 符号表（ELSP/LIO）、payload 思路 |
| [Kirin-Tool](https://kirintool.cfd)（BUSL 1.1） | Kethily Daniel & NDXCode | ktl 载荷格式原始实现与 null.ktl（本仓库不分发其任何文件） |

## License

MIT — 见 [LICENSE](LICENSE)
