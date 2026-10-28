# DHCP records from a relay agent are attributed to the relay, not the client

**Labels:** bug, parser, dhcp · **Affects:** `demo-v0.3.2`, `main` (f21e478), `spike/fingerbank-format` (8a6fe8c)

## Summary

When DHCP passes through a relay agent, which is standard on routed hospital
networks, TapirXL credits the relayed copies of client messages to the
**relay's** MAC. The relay host then acquires a client's hostname (option 12),
DHCP fingerprint and lease, while the client loses half its DHCP evidence.
Downstream this produces a router asset named after a medical device, and
BlueFlow rejects it because the hostname already belongs to the real device.

## Reproduce

```bash
uv run pytest tests/unit/test_dhcp_relay_scenario.py -rxX
```

The fixture is `tests/fixtures/dhcp_relay_scenario.pcap`; its builder is
`build_dhcp_relay_scenario.py`. Two clients on two VLANs get leases through one
router-on-a-stick, and the capture sees each client message twice: the
client's broadcast and the relay's unicast copy. Today:

| Host | `hostname` | DHCP option 12 values in its envelope |
|---|---|---|
| `00:09:fb:30:00:07` (client) | `ICU-MON-07` | its own (2 of 8 frames) |
| `00:0e:2f:40:00:02` (client) | `LAB-ANALYZER-02` | its own (2 of 8 frames) |
| `00:1c:73:0a:00:01` (**relay router**) | **`ICU-MON-07`** | **both clients'** (8 frames) |
| `00:50:56:0a:00:12` (DHCP server) | — | both clients' (4 replies) |

On the Brookhaven test range the same pattern made the core router appear in
BlueFlow as `ct01`, then `iPhone`, and flip IPs between its VLAN gateways. Every
upsert then collided with the real device's hostname: 400 on BlueFlow 0.3.x, and
500 on BlueFlow latest. The 500 also stalls the Vector sink, which retries 500s
with concurrency 1.

## Root cause

1. **Ethernet source wins over `chaddr`.** In `parser/_helpers.py`,
   `_packet_src_identity`:

   ```python
   mac = eth_mac or dhcp_mac
   ```

   A relayed frame's Ethernet source is the relay. RFC 2131 §4.1 has the relay
   leave `chaddr` and the client's options untouched and set `giaddr`, so the
   client's identity is only in the DHCP header. `src_ip` likewise comes from
   `ip.src`, which is the relay's address.

2. **The `chaddr` fallback is dead code.** It reads `getattr(packet, "bootp")`
   and the fields `hardware_mac_address`, `mac_addr` and `client_mac_address`.
   Wireshark renamed the BOOTP dissector to `dhcp` in 3.0. Through
   `PysharkSource` the fixture's layers are `['eth', 'ip', 'udp', 'dhcp']`, with
   no `bootp`. `chaddr` is `packet.dhcp.hw_mac_addr`, and `giaddr` is
   `packet.dhcp.ip_relay`. The same dead `getattr(packet, "bootp", None)`
   appears in `extractors/dhcp.py`.

3. **No relay coverage.** Every fixture is a flat single segment where the
   client is always the Ethernet source.

## Proposed fix

- **Key DHCP records by `chaddr`.** For DHCP, resolve the host from
  `packet.dhcp.hw_mac_addr` (keeping the legacy `bootp` names as a fallback for
  old tshark), not from `eth.src`. Server replies carry the client's `chaddr`
  too, so they credit the client. Their lease data belongs to the client (see
  `docs/issues/dhcp-client-identity.md`).
- **Detect relaying** when `giaddr` (`packet.dhcp.ip_relay`) `!= 0.0.0.0`, or when `eth.src != chaddr` on a
  client message. Record the sender as a relay observation, for example
  `dhcp_relay: {giaddr, observed_by}`, on the Ethernet-source host. That is a
  real topology signal: the router serves that subnet. The relay never inherits
  option 12, 55 or 60.
- **No envelope key changes:** envelopes stay keyed by MAC (N8). This only
  changes which MAC a DHCP record is filed under.
- **Remove the dead `bootp` paths,** or keep them explicitly as a
  legacy-tshark fallback with a comment.

## Acceptance

- In `tests/unit/test_dhcp_relay_scenario.py`, these three tests XPASS (strict),
  and their `xfail` markers are removed in the fix PR:
  - `test_relay_router_gets_no_client_hostname`
  - `test_no_host_carries_another_hosts_option12`
  - `test_relayed_copies_credit_the_client`
- `test_each_client_gets_its_own_hostname` still passes.
- The golden regressions (`tests/regression/test_golden*.py`) are unchanged:
  their captures contain no relayed frames.
- A unit test asserts `chaddr` is read from a current-tshark `dhcp` layer.

## Notes

- The DHCP server's envelope also collects clients' option 12 from its own
  replies. Crediting replies by `chaddr` fixes that in the same change.
- This is unrelated to the 2026-10-26 Brookhaven fabric outage. That was a
  range issue.
