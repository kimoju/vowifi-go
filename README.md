# vowifi-go

An independent, open implementation of the VoHive VoWiFi runtime boundary.

This repository intentionally starts with the public API surface consumed by
VoHive:

- SIM AKA contracts under `engine/sim`
- dataplane constants under `engine/swu`
- runtime lifecycle, state, modem access, and service wrappers under
  `runtimehost`
- carrier policy and E911 request contracts under `runtimehost/carrier` and
  `runtimehost/e911`
- SMS, USSD, event dispatch, and voice gateway integration helpers under
  `runtimehost/messaging`, `runtimehost/eventhost`, and `runtimehost/voicehost`

The current implementation includes the runtime boundary plus the first real
protocol layers needed by VoHive:

- logical-channel SIM/ISIM APDU helpers, FCP/TLV parsing, ISIM identity EF
  reading, and USIM/ISIM AKA AUTHENTICATE primitives
- carrier presets and JSON carrier overrides, including AT&T TS.43/E911
  configuration for native `310/280` and `310/410` profiles
- TS.43-style E911 entitlement bootstrap, token/websheet handling, and
  RAND/AUTN challenge response through the AKA provider
- IMS SIP client primitives for REGISTER headers, `WWW-Authenticate` parsing,
  AKA nonce extraction, and Digest/AKAv1-MD5 authorization generation
- SMS, USSD, event dispatch, and voice gateway integration helpers used by
  VoHive

IKE/IPsec transport establishment, full IMS registration state machines, and
media bridging are still implemented incrementally behind these APIs.

## Development

```sh
go test ./...
```

VoHive can use this repository through its workspace:

```go
replace github.com/iniwex5/vowifi-go v1.1.2 => ../vowifi-go
```
