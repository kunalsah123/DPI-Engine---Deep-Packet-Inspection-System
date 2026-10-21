# Packet Analyzer DPI (Node.js)

A modular, dependency-free Node.js port of the Packet Analyzer DPI project. It reads classic PCAP captures, parses Ethernet/VLAN, IPv4/IPv6, TCP and UDP, inspects TLS SNI, HTTP Host and DNS query names, tracks bidirectional flows, applies blocking rules and optionally writes a filtered capture.

## Requirements and setup

- Node.js 18 or newer
- No third-party npm modules are required

```sh
npm install
```

`npm install` prepares the local npm project; the analyzer uses only Node.js built-in modules.

## Run

```sh
npm start -- ./test_dpi.pcap
npm start -- ./test_dpi.pcap ./filtered.pcap --block-app YouTube
npm start -- ./filtered.pcap --json
```

Without an output path, the program analyzes the input and prints a report. `--json` prints a JSON report.

### Rules

```sh
npm start -- ./input.pcap ./filtered.pcap \
  --block-app YouTube \
  --block-ip 192.168.1.50 \
  --block-domain facebook \
  --block-port 25
```

Rules may be repeated. Source IP and port rules can match immediately. App/domain rules take effect once the analyzer can identify the flow from TLS SNI or an HTTP Host header. Packets already written before the domain is learned cannot be removed retroactively; later packets in that flow are dropped.

`--max-packets N` limits the number of capture records inspected. `--lbs N` and `--fps N` select deterministic logical flow shards and report their distribution. Node's event loop processes these shards on the main thread; they do not create parallel CPU worker threads.

## Module map

The original C++ `include/` declarations and `src/` implementations are represented by JavaScript modules in `src/`. JavaScript modules export their public functions/classes directly, so a separate header directory is not needed.

| Node.js module | Responsibility |
|---|---|
| `pcap_reader.js` | Read classic PCAP headers and packet records; write forwarded records |
| `packet_parser.js` | Decode Ethernet/VLAN, IPv4/IPv6, TCP/UDP and payload boundaries |
| `sni_extractor.js` | Inspect TLS ClientHello SNI, HTTP Host and DNS query names |
| `types.js` | Application signatures and bidirectional flow key helpers |
| `rule_manager.js` | Add, remove and evaluate IP/app/domain/port rules |
| `connection_tracker.js` | Track flow classification, byte/packet counts, blocked state and expiry |
| `thread_safe_queue.js` | Bounded asynchronous producer/consumer queue for Node event-loop work |
| `load_balancer.js` | Deterministically assign both directions of a flow to the same logical shard |
| `fast_path.js` | Classify a packet, update its flow and decide forward/drop |
| `dpi_engine.js` | Coordinate reader, parser, sharding, fast paths, rules, stats and output |
| `platform.js` | Link-layer/platform capability metadata |
| `main.js` | CLI argument parsing and human/JSON reporting |
| `main_packet.js` | Packet-by-packet header/payload inspection (former `main.cpp`) |
| `main_dpi.js`, `main_simple.js`, `main_working.js` | Compatibility entry points that reuse the shared DPI engine |
| `dpi_mt.js` | Former multithreaded CLI entry point with configurable logical shards |
| `index.js` | Public exports for using the analyzer as a Node.js module |

`npm run generate:pcap` creates a sample capture using `generate_test_pcap.js`.

## Supported capture formats

Classic PCAP with microsecond or nanosecond timestamps; Ethernet, raw IPv4 and raw IPv6 link types. Unsupported link-layer packets pass through. PCAPNG is not supported. This tool filters saved capture files; it does not capture or block live browser traffic.
