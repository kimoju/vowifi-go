# vowifi-go

本页是 [README.md](README.md) 的中文同步版本。项目默认文档语言为英语；如中英文表述存在细微差异，请以英文文档为准。

`vowifi-go`（`github.com/kimoju/vowifi-go`）是面向 [VoHive](https://github.com/kimoju/vohive) 的第三方独立开源 Go 语言 3GPP VoWiFi / IMS 运行时协议栈实现。

本仓库提供 VoHive 所需的公开运行时宿主 API 与核心协议引擎，涵盖 USIM/ISIM AKA 鉴权、SWu/ePDG IPsec 隧道、IMS SIP 注册与 `sec-agree` 安全协商、VoWiFi 语音与 SRTP 媒体桥接、SMS over IP 短信、IMS USSD 以及 GSMA TS.43 E911 紧急业务准入。

## 核心能力概览

| 领域 | 已实现核心特性 |
| --- | --- |
| **SIM / ISIM 与 AKA** | 逻辑通道 APDU（`AT+CCHO`/`CGLA`/`CCHC`、QMI `UIM`、PC/SC）、`AT+CRSM`（`61xx`/`6Cxx` 自动追取与 4 KiB 分块读取）、BER-TLV `0x80` ISIM 身份读取、2/3 位 `EF_AD` MNC 精确隔离、ETSI `0x9862` MAC 错误识别、带 `AUTS` 重同步的 USIM/ISIM AKA 鉴权、Luhn 校验 IMEI 与 `-0` `+sip.instance` 生成 |
| **SWu / ePDG IPsec** | `IKEv2`（`IKE_SA_INIT`、`IKE_AUTH`、`CREATE_CHILD_SA`、`INFORMATIONAL`、`MOBIKE`）、响应方 X.509 / RSA / ECDSA / RFC 7427 证书签名校验与 `EAP_ONLY_AUTHENTICATION`、带预送卡 `AT_KDF_INPUT` / `AT_CHECKCODE` 防护的 `EAP-AKA'` / `EAP-AKA`、RFC 7383 `SKF` 加密分片收发、双向 IKE/Child SA Rekey、加盐单调 AES-GCM IV 与 64-bit ESN 防重放窗口、3GPP `16384`/`16386` P-CSCF 与 17B IPv6 CP 属性解析、Linux `XFRM` / 非阻塞 `TUN`（含 MTU/MSS 钳制与 ICMP PTB）/ 带 TCP 保活的 `SOCKS5 UDP` 隧道模式 |
| **IMS 注册与 SIP 核心** | IPv4/IPv6 双栈 UDP/TCP SIP 传输（超 `1300B` 或 `513 Message Too Large` 自动无缝切换 TCP）、Digest MD5/SHA-256/SHA-512-256 与 AKAv1/v2-MD5、IMS `sec-agree`（监听端口重绑与 XFRM SA/SP 全生命周期管理）、RFC 3680 `Event: reg` 注册状态订阅、`_sip._udp`/`_tcp` SRV + A/AAAA 故障切换、CRLF 保活与优雅注销 |
| **VoWiFi 语音与媒体** | 呼出与呼入 IMS 会话桥接、3GPP `100rel`/`PRACK`、资源预留 `precondition`（`183`/`PRACK`/`UPDATE`）、`Session-Expires`（`422 Min-SE` 重试）、对话内 `re-INVITE`/呼叫保持/`BYE`/`REFER`/`NOTIFY`/`INFO`、Glare 冲突与延迟 `CANCEL` 处理、`RTP/AVP` ↔ `RTP/SAVP`（`SDES` AES-CM / AEAD-AES-GCM）双向 SRTP/SRTCP 加解密中继、复合 `RTCP` 质量报告及 RFC 4733 `DTMF` |
| **IMS 短信、USSD 与 MWI** | 3GPP `application/vnd.3gpp.sms` 与 `message/cpim` / IMDN 封装解包、8/16-bit UDH 长短信分片与国家语言移位表、半八位组/GSM-7 地址编解码、异步 `RP-ACK`/`RP-ERROR` 与状态报告、交互式 `<UnstructuredSS-Request>`/`Notify` IMS USSD 会话以及 RFC 3842 `message-summary` 语音信箱指示 |
| **运营商策略与 E911** | 内置多运营商预设与 JSON 覆盖配置、GSMA TS.43 HTTP Digest AKA / EAP-AKA' 准入协商（兼容 JSON、OMA XML 与 Apple Plist 响应）、`Set-Cookie`/`nextnonce` 会话保持、Websheet 令牌流程与 `multipart/related` PIDF-LO 紧急呼叫辅助 |

## 项目状态

`vowifi-go` 仍在持续演进中。本项目与任何模组/终端厂商、电信运营商或官方闭源 VoWiFi 实现均无官方关联、授权或背书关系，亦不声称具备与所有现网运营商策略的完全等价替代性。真实硬件与运营商网络兼容性验收标准请参见 [VoHive 可用性评估](docs/VOHIVE_READINESS.md)。

## 快速开始

运行全量竞态检测测试：

```sh
go test -race ./...
```

运行与 GitHub Actions 完全一致的本地 CI 检查（Go 版本、模块路径、隐私与仓库卫生检查、`gofmt`、`go vet`、VoHive 兼容自测及全量单测）：

```sh
make ci
```

在消费方 `go.mod` 中引入或更新：

```sh
go get github.com/kimoju/vowifi-go@latest
```

本地与 VoHive 联调验证可执行 `make compat-vohive`（脚本会在隔离的临时副本中注入本地替换并执行构建与测试，不会污染工作区 `go.mod`）。

## 文档导航

- [功能清单](docs/FEATURES.md) - 当前详细协议实现列表与已知边界。
- [VoHive 可用性评估](docs/VOHIVE_READINESS.md) - 真实设备与现网联调验收清单。
- [架构说明](docs/ARCHITECTURE.md) - 包职责划分、运行时边界与高层工作流。
- [开发指南](docs/DEVELOPMENT.md) - CI 目标、本地验证与多模块工作区用法。
- [英文免责声明](docs/DISCLAIMER.md) 与 [中文免责声明](docs/DISCLAIMER.zh-CN.md)。

## 免责声明摘要

`vowifi-go` 仅供个人学习、通信技术研究与非商业功能测试使用。使用者需自行确保符合所在国家/地区法律法规、电信运营商服务条款、无线电与终端管理要求。本软件按“现状（AS IS）”提供，不附带任何明示或暗示担保；因使用、误用、部署或无法使用本项目造成的任何损失，作者及贡献者均不承担责任。

使用前请务必阅读完整的 [中文免责声明](docs/DISCLAIMER.zh-CN.md)。
