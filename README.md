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

The current implementation is a working runtime scaffold for VoHive development:
it compiles, starts, exposes state, routes SMS/USSD calls through stable
interfaces, and provides a SIP-compatible voice gateway boundary. Carrier-grade
IKE/IPsec, IMS registration, entitlement challenge handling, and media bridging
are designed as future implementation layers behind these APIs.

## Development

```sh
go test ./...
```

VoHive can use this repository through its workspace:

```go
replace github.com/iniwex5/vowifi-go v1.1.2 => ../vowifi-go
```
