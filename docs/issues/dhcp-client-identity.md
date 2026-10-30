# DHCP client identity: unparsed message type, unused lease address, sticky hostname

**Status:** fixed on `fix/dhcp-relay-attribution`, except the spike-branch AE-title item; see "Resolution".
**Labels:** bug, parser, dhcp · **Affects:** `demo-v0.3.2`, `main` (f21e478); the hostname fallback also affects `spike/fingerbank-format` (8a6fe8c)
**Depends on:** `docs/issues/dhcp-relay-attribution.md`, which decides *which
host* a DHCP record belongs to. This issue covers *what* TapirXL takes from the
record once it is filed under the right host.

## Summary

Three weaknesses in how a host's identity is built from DHCP, all visible in
`tests/fixtures/dhcp_relay_scenario.pcap`:

1. **The leased address is never used.**
   - Clients that only speak DHCP come out with `ip_address = "0.0.0.0"`.
     `src_ip` of a client message is 0.0.0.0 before the lease, and the server's
     `yiaddr` is ignored.
   - `DhcpBlock.lease_yiaddr` exists in the schema but is always `null`.
2. **The message type is scraped from `pretty_print()` text with a regex.** An
   unrecognised type becomes `""`, and the hostname filter treats `""` as a
   client message (`envelope_builder.py`: `if msg_t in ("discover", "request", "")`),
   so the filter fails open.
3. **The first hostname wins forever.** `if h and not env.get("dhcp_hostname")`
   keeps the first option 12 for the life of the process.
   - A renamed device, or a misattributed record, is never corrected.
   - In live mode a wrong first value persists until restart. That is how the
     relay router in the companion issue kept a client's name.

## Reproduce

```bash
uv run pytest tests/unit/test_dhcp_relay_scenario.py -rxX
```

`test_client_ip_is_its_leased_address` (strict xfail) expects
`10.50.30.107` and `10.50.40.102`. Today both clients report `0.0.0.0`.

## Proposed fix

- **Message type from option 53:** read `packet.dhcp.option_dhcp` (field
  `dhcp.option.dhcp`: 1 Discover … 8 Inform) instead of regexing the
  pretty-printed text. Keep the regex only as a fallback, and treat "unknown"
  as *not* a client message. A missing type must not admit a hostname.
- **Lease address:** on Offer (2) and ACK (5), record `yiaddr`
  (`packet.dhcp.ip_your`) as `lease_yiaddr` on the `chaddr` host's `DhcpBlock`.
  Add it to the host's `ip_observations`, ACK taking precedence over Offer. The
  host IP rollup (`env["ip"]` in `envelope_builder.finalize_envelope_from_records`)
  should prefer an observed non-zero address and fall back to the ACKed lease,
  never `0.0.0.0`.
- **Hostname choice:**
  - Prefer the **latest** client-originated option 12 (Discover, Request,
    Inform) over the first.
  - Never accept option 12 on a host seen acting as a relay (companion issue).
  - Optionally record a hostname change as an event, rather than overwriting
    silently.
- **Related (spike branch only):** `_derive_hostname` on
  `spike/fingerbank-format` falls back to `dicom_ae_calling`. AE titles aren't
  unique: Philips CTs default to `DATABASE`. Two CTs would get the same hostname
  and collide in BlueFlow's unique-hostname constraint. Keep the AE title in its
  own field (it is already `dicom_ae_calling`) and drop it from the hostname
  fallback chain.

## Acceptance

- `test_client_ip_is_its_leased_address` XPASSes (strict) and its marker is
  removed in the fix PR.
- New unit tests cover:
  - message type from option 53 for all 8 types;
  - "unknown" type rejecting option 12;
  - a later client hostname replacing an earlier one.
- The golden regressions (`tests/regression/test_golden*.py`) are unchanged, or
  updated in the same PR with the `ip_address` difference explained.
  InventoryRecord field semantics must not change otherwise (N9).

## Resolution

- **Message type:** `extractors/dhcp.handle()` reads option 53
  (`packet.dhcp.option_dhcp`), with the pretty-print regex kept only as a
  fallback for layers without the field. On the fixture it decodes
  discover, offer, request and ack for every frame.
- **Lease:**
  - `handle()` records `yiaddr` (`packet.dhcp.ip_your`) as `lease_yiaddr` on
    Offer and ACK, and it is serialized into `DhcpBlock.lease_yiaddr`.
  - In `envelope_builder`, an ACKed lease is added to `ip_observations`.
  - An Offer is kept only as the last-resort IP fallback, because a client can
    decline it.
  - `env["ip"]` prefers an observed address, then the ACKed lease, then the
    offered one.
  - The unit tests caught a first version that let an earlier Offer beat the
    ACK.
- **Hostname:**
  - Only Discover, Request and Inform (`DHCP_CLIENT_MESSAGES`) set
    `dhcp_hostname`, and the latest one wins.
  - An unknown type no longer admits a name.
  - Relay and server sender records carry no option 12
    (`docs/issues/dhcp-relay-attribution.md`), so relays never acquire one.
- **Goldens:**
  - The inventory and assets goldens are byte-identical.
  - The envelope golden was regenerated, and the only difference is
    `lease_yiaddr` filled on each client's Offer and ACK blocks.
- **Range check** (Brookhaven, 30 min, 8,019 packets): 21 records, none at
  `0.0.0.0`; every DHCP client is named correctly, and the router and switches
  carry no hostname.
- **Not done here:** the `dicom_ae_calling` hostname fallback exists only on
  `spike/fingerbank-format`. Drop it from `_derive_hostname` there before that
  branch merges.
