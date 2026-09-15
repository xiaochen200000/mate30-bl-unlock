# mate30-bl-unlock

华为 **Mate30（麒麟 990 4G，Taurus）** bootloader（BL）解锁方案与配套工具集。
从 BootROM 漏洞出发 → 注入回调 → 回读 xloader / fastboot 明文 → 补丁解锁，全链路脚本与文档。

> **⚠️ 免责声明**
> 本项目仅用于**对自己拥有的设备**进行安全研究与救砖。刷写/补丁引导链存在变砖风险，
> 造成的任何损失由使用者自行承担。解锁后设备失去官方安全更新与银行/政务类应用兼容性，
> 且可能违反当地保修条款。请勿用于他人设备或任何违法用途。

---

## 方案速览

```
[BootROM] FRESH 会话(07)
   │  null.ktl 解密产物 @0x22000 + 线缆舞步 (TP4009 OFF 3s ON)
   ▼
[BootROM] 喂官方 BD 包 sec_usb_xloader.img → 设备端解密器原位解密运行
   │  ★利用点: BootROM 下载协议 HEAD 帧 ADDRESS 字段不校验
   │           → head 重发式任意写 (bug2_write)
   ▼
[SRAM 注入] 回调 payload @0x5C400（CD 应答劫持 + 分发器 + 向量表 + 休眠返回链喷涂）
   │  触发: 纯静默 150s x2（xloader 版）/ 关串口 3s（fastboot 版）
   ▼
[收割] CD 应答按 4B/次送回明文
   ├── readback_xloader.py  → xloader 明文 (192KB,  ELF)
   └── readback_fastboot.py → fastboot 明文 (4.67MB, DDR @0x3A400000)
   ▼
[解BL] 对明文 fastboot 定位锁函数 → 运行期补丁 → oem unlock 任意码
        （补丁表与机制论证见 docs/03）
```

- **漏洞链**: BootROM 任意写 → xloader 阶段 HEAD 地址不校验 → 任意读（docs/05）
- **锁机制**: FB Lock（`rdmode` NV）+ USER Lock（NV 0x5D）双层锁（docs/02）
- **补丁方案**: P1 任意码解锁 + 命令门/logo/AVB/certify 放行，共 7 处补丁（docs/03）
- **锁函数定位方法论**: 无符号明文里锚点字符串 → xref → 补丁模板（docs/04）

## 仓库结构

```
├── README.md                 ← 你在这里
├── docs/
│   ├── 01-protocol.md                 底层 USB 协议速查（CD/HEAD/DATA/TAIL 帧、补丁表）
│   ├── 02-lock-mechanism.md           FB Lock / USER Lock 双层锁分析
│   ├── 03-unlock-patch-plan.md        ★解BL补丁方案（P1 任意码 + 全补丁表）
│   ├── 04-fastboot-lock-locating.md   无符号 fastboot 明文的锁函数定位方法论
│   ├── 05-xloader-arbitrary-read.md   xloader 任意读漏洞定案
│   └── 06-bootrom-xloader-analysis.md BootROM / xloader 逆向全记录
├── tools/                    ★可直接使用的脚本（交互式进度反馈）
│   ├── console_ui.py                  控制台 UI 组件（零依赖）
│   ├── config.example.ini             配置样例 → 复制为 config.ini 填写
│   ├── readback_xloader.py            xloader 明文回读（proven 配置重构版）
│   └── readback_fastboot.py           fastboot 明文回读（DDR 版，4.67MB 整取）
├── research/                 研究用底层材料
│   ├── xloader_send.py                xloader 下载协议库（XMODEM 帧/CRC/进度回调）
│   ├── PROTOCOL.md                    xloader 下载协议完整逆向记录
│   └── ar_read_poc.py                 任意读 PoC（分阶段: probe/selftest/arm/scan/dump/restore）
└── probes/                   设备诊断小工具（fastboot 原始命令 / dd 备份 / dump 扫描 / 端口监听）
```

## 环境要求

- Windows 10+（用到 `winsound`、USB CDC 驱动行为）
- Python 3.10+
- `pip install pyserial keystone-engine`
- 华为 USB Download Mode 驱动（设备进下载模式后 Windows 自动识别为 COM 口，VID 0x12D1 / PID 0x3609）

## 自备组件（本仓库**不**分发，原因见下节）

| 组件 | 用途 | 获取方式 |
|---|---|---|
| 官方 BD 刷机包（Taurus-AL00B BD 1.0.0.33） | 提供 `sec_usb_xloader.img` 等 | 华为官方渠道自取，解压出 `bootloaderimage` 目录 |
| `kirin_loader.py` + `null.ktl` | null 载荷解密（`dtl()`） | Kirin-Tool（FirmwareUnlocker）的 Python 移植，含第三方密钥材料 |

**为什么不随仓库分发**：固件文件有版权；Kirin-Tool 模块内嵌第三方项目的密钥材料——
搬运他人密钥既不合适，也会把使用者暴露在法律风险下。参考同类工作请访问上游而非索取拷贝。

把 `kirin_loader.py` 放到任意目录，将路径填入 `tools/config.ini` 的 `kirin_module_dir` 即可。

## 使用方法

```bash
# 0) 复制配置样例并填写路径
cd tools
copy config.example.ini config.ini   # 然后编辑 config.ini

# 1) 回读 xloader 明文（设备进下载模式后插线）
python readback_xloader.py            # 首轮等待设备 600s；--nowait 只等 30s
# 成功后得到 XLOADER_BD_PLAIN.bin（192KB ELF，可用 Ghidra/IDA 直接分析）

# 2) 回读 fastboot 明文（4.67MB 整取）
python readback_fastboot.py
# 成功后得到 FASTBOOT_PLAIN.bin（可配合 docs/04 定位锁函数）

# 3) 任意读 PoC（研究用，分阶段可中止）
python ar_read_poc.py          # 无参数看帮助: probe/selftest/arm/scan/dump/restore
```

两个回读工具均带**实时进度反馈**：阶段横幅、进度条（速率）、静默等待倒计时、
每一步的 OK/FAIL 判定与蜂鸣提示；失败自动进入下一轮（默认最多 40 轮），Ctrl+C 随时安全中断。

## 已验证范围（重要）

- 机型: **Mate30 4G（Taurus-AL00B）**，BD 包 **1.0.0.33**，鸿蒙/EMUI 引导链
- 其他机型/其他 BD 版本：payload 地址表（0x5C400 系列）、补丁偏移、DDN 驻留地址**都可能不同**，
  需要用 docs/04 的方法论自行核对，直接照跑大概率失败——脚本失败是安全的（不动设备持久状态）。

## 隐私与安全

本仓库**不包含**任何密钥、token、固件、设备序列号、dump 文件；`.gitignore` 已把
`config.ini`、`kirin_loader*.py`、`*.ktl`、所有二进制全部排除。提交前经过敏感信息扫描。

给你（使用者）的提醒：**不要**在 issue/讨论里粘贴含设备序列号的日志，不要把自己改过路径的
`config.ini` 发给别人——路径里往往带着你的用户名。

## 致谢与引用

- [XingChenRS/kirin9905Gexploit](https://github.com/XingChenRS/kirin9905Gexploit)（MIT）——麒麟990 5G BootROM 漏洞复现与 dump，本文档多处参考其符号表
- MOSEC 2021「checkm30」——海思 BootROM 漏洞公开演讲（上游仓库已失效，可搜索存档）
- TASZK — *Unicorns to the Slaughterhouse*（BlackHat USA 2021）——海思启动链安全研究白皮书
- Kirin-Tool（FirmwareUnlocker）——ktl 载荷格式的原始实现

以上第三方内容本仓库只引用链接，不再分发其文件。

## License

MIT — 见 [LICENSE](LICENSE)
