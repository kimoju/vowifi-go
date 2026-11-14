# vowifi-go

An independent, open Go implementation of the [VoHive](https://github.com/kimoju/vohive) 3GPP VoWiFi / IMS runtime boundary (`github.com/kimoju/vowifi-go`).

This repository provides the protocol engines and public runtime host APIs consumed by VoHive for USIM/ISIM AKA authentication, SWu/ePDG IPsec tunneling, IMS SIP registration and `sec-agree`, VoWiFi voice/SRTP media bridging, SMS over IP, IMS USSD, and GSMA TS.43 E911 entitlement.

## Capabilities Overview

| Area | Implemented Highlights |
| --- | --- |
| **SIM / ISIM & AKA** | Logical-channel APDU (`AT+CCHO`/`CGLA`/`CCHC`, QMI `UIM`, PC/SC), `AT+CRSM` (`61xx`/`6Cxx`, 4 KiB chunking), BER-TLV `0x80` ISIM identity reads, 2/3-digit `EF_AD` MNC isolation, ETSI `0x9862` MAC error handling, USIM/ISIM AKA `AUTHENTICATE` with `AUTS` resync, Luhn-checked IMEI & `-0` `+sip.instance` |
| **SWu / ePDG IPsec** | `IKEv2` (`IKE_SA_INIT`, `IKE_AUTH`, `CREATE_CHILD_SA`, `INFORMATIONAL`, `MOBIKE`), responder X.509 / RSA / ECDSA / RFC 7427 signature verification & `EAP_ONLY_AUTHENTICATION`, `EAP-AKA'` / `EAP-AKA` with pre-USIM `AT_KDF_INPUT` / `AT_CHECKCODE` validation, RFC 7383 `SKF` encrypted fragmentation, bidirectional IKE/Child SA rekey, salted monotonic AES-GCM IV & 64-bit ESN anti-replay, 3GPP `16384`/`16386` P-CSCF & 17-byte IPv6 CP attributes, Linux `XFRM` / non-blocking `TUN` (MTU/MSS clamping & ICMP PTB) / `SOCKS5 UDP` relay with TCP control keepalive |
| **IMS Registration & SIP** | Dual-stack UDP/TCP SIP flows with automatic `>1300B` / `513` UDP-to-TCP fallback, Digest MD5/SHA-256/SHA-512-256 & AKAv1/v2-MD5, `Security-Client`/`Server`/`Verify` (`sec-agree`) with live listener rebind & XFRM SA/SP lifecycle, RFC 3680 `Event: reg` `SUBSCRIBE`/`NOTIFY`, `_sip._udp`/`_tcp` SRV + A/AAAA failover, CRLF NAT keepalive, and graceful `Expires: 0` de-registration |
| **VoWiFi Voice & Media** | Outbound & inbound IMS dialogs, 3GPP `100rel`/`PRACK`, `precondition` (`183`/`PRACK`/`UPDATE`), `Session-Expires` (`422 Min-SE`), mid-dialog `re-INVITE`/hold/`BYE`/`REFER`/`NOTIFY`/`INFO`, glare `491` & deferred `CANCEL` handling, `RTP/AVP` ↔ `RTP/SAVP` (`SDES` AES-CM / AEAD-AES-GCM) SRTP/SRTCP media relay, compound `RTCP` reports/feedback, and RFC 4733 `telephone-event` DTMF |
| **SMS over IP, USSD & MWI** | 3GPP `application/vnd.3gpp.sms` & `message/cpim` / IMDN wrapping, 8/16-bit UDH concatenation & national language shift tables, semi-octet/GSM-7 `TP-OA`/`TP-DA`, async `RP-ACK`/`RP-ERROR` & `SMS-STATUS-REPORT`, interactive `<UnstructuredSS-Request>`/`Notify` IMS USSD dialogs, and RFC 3842 `message-summary` MWI |
| **Carrier Policy & E911** | Built-in carrier presets & JSON overrides, GSMA TS.43 HTTP Digest AKA / EAP-AKA' entitlement bootstrap (JSON, OMA XML, and Apple Plist), `Set-Cookie`/`nextnonce` session continuity, token/websheet flows, and `multipart/related` PIDF-LO emergency SIP helpers |

## Status

`vowifi-go` is under active development. It is not affiliated with, endorsed by, or a drop-in replacement for any device vendor, telecom operator, or closed-source VoWiFi SDK. Carrier-specific interworking and real-network validation continue to evolve incrementally behind the public runtime APIs; see [VoHive readiness](docs/VOHIVE_READINESS.md) for validation criteria.

## Quick Start

Run the full unit test suite (with race detector):

```sh
go test -race ./...
```

Run the local CI gate used by GitHub Actions (version, module-path, privacy/hygiene, formatting, `go vet`, compatibility self-test, and unit tests):

```sh
make ci
```

Install or update in a Go module consumer:

```sh
go get github.com/kimoju/vowifi-go@latest
```

For local cross-repo validation against a VoHive checkout without committing local `replace` directives, run `make compat-vohive` (creates an isolated temporary copy for testing).

## Documentation

- [Features](docs/FEATURES.md) - detailed implementation inventory and known gaps.
- [VoHive readiness](docs/VOHIVE_READINESS.md) - hardware/carrier integration checklist.
- [Architecture](docs/ARCHITECTURE.md) - package layout, runtime boundaries, and protocol flow.
- [Development](docs/DEVELOPMENT.md) - CI targets, local validation, and workspace usage.
- [Disclaimer](docs/DISCLAIMER.md) - legal, compliance, warranty, and operational-risk notice.
- [Chinese README](README.zh-CN.md) and [Chinese disclaimer](docs/DISCLAIMER.zh-CN.md).

## Disclaimer Summary

`vowifi-go` is provided strictly for personal learning, technical research, and non-commercial functional testing. Users are solely responsible for complying with local laws, telecom operator terms, device regulations, and network policies. The software is provided "as is", without warranties of any kind, and the authors and contributors assume no liability for any direct or indirect damages arising from its use or inability to use.

Read the full [Disclaimer](docs/DISCLAIMER.md) before using this project.
