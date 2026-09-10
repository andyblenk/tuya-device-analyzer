# Tuya Device Analyzer

**Tuya Device Analyzer** is a read-only command-line tool for diagnosing Tuya
and Smart Life devices on the local network. It identifies the Tuya LAN
protocol and query mode a device actually supports, reads its available
datapoints (DPs), and creates reports that help troubleshoot Home Assistant
integrations such as LocalTuya.

It is especially useful when a device is reachable but Home Assistant reports
it as unavailable, or LocalTuya shows:

> Connection to device succeeded but no datapoints found.

The analyzer supports Tuya LAN protocols **3.1 through 3.5** and uses
[TinyTuya](https://github.com/jasonacox/tinytuya) for protocol communication.

## Why this tool exists

A successful connection to port 6668 does not prove that an integration can
communicate with a Tuya device. Different hardware and firmware generations can
use different encryption, framing, session-key negotiation, and status-query
formats.

This can produce confusing symptoms:

- The device works in Smart Life but is unavailable in Home Assistant.
- The official cloud integration works while LocalTuya does not.
- A device accepts the connection but returns no datapoints.
- LocalTuya reports `Unexpected Payload from Device`.
- LocalTuya reports `Check device key or version`.
- Manually entering datapoints does not resolve the connection problem.

The analyzer tests the relevant combinations systematically instead of
requiring repeated trial and error in Home Assistant.

## Features

- Checks the common Tuya TCP ports `6668`, `6669`, and `8681`.
- Performs Tuya LAN discovery.
- Tests protocol versions 3.1, 3.2, 3.3, 3.4, and 3.5.
- Tests standard, `device22`, and multiple alternative Tuya 3.5 status-query
  behaviors.
- Accepts a device-specific DP list without embedding product-specific logic.
- Tests DPs as a batch and in configurable chunks.
- Requests explicit DP updates and listens for active device reports.
- Runs read-only heartbeat, status, product, and DP-detection requests.
- Queries common and extended datapoints.
- Records response times and exact exception types.
- Captures redacted TinyTuya protocol-level debug output.
- Shows live console progress while writing log and JSON reports.
- Finishes automatically after all variants have been tested.

### Protocol selectors

| Selector | Wire protocol | Query mode |
|---|---:|---|
| `3.1` | 3.1 | standard |
| `3.2` | 3.2 | `device22` |
| `3.3` | 3.3 | standard |
| `3.22` | 3.3 | `device22` |
| `3.4` | 3.4 | standard |
| `3.42` | 3.4 | `device22` |
| `3.5` | 3.5 | standard |
| `3.5-data-dps` | 3.5 | `{"data":{"dps":{}}}` payload |
| `3.5-explicit-dps` | 3.5 | identity, timestamp, and explicit null DP map |
| `3.5-explicit-chunks` | 3.5 | explicit null DP map in small groups |
| `3.5-protocol-dps` | 3.5 | protocol wrapper and explicit null DP map |
| `3.5-dpid-list` | 3.5 | explicit `dpId` list |
| `3.5-updatedps` | 3.5 | `UPDATEDPS` request followed by passive receive |
| `3.5-updatedps-chunks` | 3.5 | chunked `UPDATEDPS` requests and receives |
| `3.5-passive` | 3.5 | bounded observation of unsolicited reports |
| `3.52` | 3.5 | `device22` |

Selectors containing a suffix are analyzer labels for alternative status
queries. They are not official Tuya wire-protocol version numbers.

Some protocol-3.5 devices reject the normal empty status payload `{}` with
`json obj data unvalid`. The `3.5-data-dps` probe tests the known read-only
alternative `{"data":{"dps":{}}}` on a fresh connection. The other 3.5
probes request the known same information using explicit DP maps or an
`UPDATEDPS` report request. They do not assign or change DP values.

The analyzer remains device-independent. Use `--dps` to supply IDs obtained
from the Tuya data model, another integration, or a previous diagnostic run.
Chunked probes can identify firmware that rejects a request when it contains
an unsupported DP. During `3.5-passive`, operate the device physically when
the console asks you to do so. This can reveal devices that report DPs only
when their state changes.

## Safety and privacy

The analyzer is deliberately **read-only**. It never sends commands that
switch a device, change a temperature, select a mode, or modify schedules,
presets, or other device state.

Use it only with devices you own or are authorized to administer.

The analyzer redacts these values from console output and generated reports:

- LocalKey
- Device ID
- device IP address
- access tokens and similar secret fields
- negotiated session keys

Reports still contain detailed device-capability and protocol information.
Review them before publishing them or attaching them to a public issue.

## Requirements

- Python 3.10 or newer
- Direct network access to the Tuya device
- Device IP address
- Tuya Device ID
- 16-character Tuya LocalKey

Tuya cloud credentials are not required.

## Installation

### macOS and Linux

```bash
git clone https://github.com/andyblenk/tuya-device-analyzer.git
cd tuya-device-analyzer
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### Windows PowerShell

```powershell
git clone https://github.com/andyblenk/tuya-device-analyzer.git
cd tuya-device-analyzer
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Usage

The safest option is to omit the LocalKey and enter it at the hidden prompt:

```bash
python tuya_device_analyzer.py \
  --ip <DEVICE_IP> \
  --device-id <DEVICE_ID>
```

You can also pass a placeholder-shaped LocalKey as an argument:

```bash
python tuya_device_analyzer.py \
  --ip <DEVICE_IP> \
  --device-id <DEVICE_ID> \
  --local-key xxxxxxxxxxxxxxxx
```

Be aware that command-line arguments can remain in shell history and may be
visible to other local processes while the analyzer is running.

Alternatively, use an environment variable:

```bash
export TUYA_LOCAL_KEY='xxxxxxxxxxxxxxxx'
python tuya_device_analyzer.py \
  --ip <DEVICE_IP> \
  --device-id <DEVICE_ID>
unset TUYA_LOCAL_KEY
```

### Options

```text
--ip ADDRESS           Device IP address (required)
--device-id ID         Tuya Device ID (required)
--local-key KEY        LocalKey; otherwise environment or hidden prompt
--timeout SECONDS      Timeout per network operation (default: 7)
--pause SECONDS        Pause between protocol variants (default: 3)
--output-dir PATH      Report directory (default: ./logs)
--dps IDS              Comma-separated DP IDs for targeted probes
--dp-chunk-size COUNT  Number of DPs per chunk (default: 5)
--listen-seconds TIME  Passive 3.5 observation time (default: 30)
-h, --help             Display the complete command reference
```

For example, to allow a slower device more time:

```bash
python tuya_device_analyzer.py \
  --ip <DEVICE_IP> \
  --device-id <DEVICE_ID> \
  --dps 1,2,3,9,10,11,12,13,14,101 \
  --dp-chunk-size 1 \
  --listen-seconds 45 \
  --timeout 10 \
  --pause 4
```

The example DP list is illustrative. Replace it with the data points of the
device being analyzed.

## Preparing a reliable test

Some Tuya devices accept only one local client connection at a time. Before
starting a test:

1. Force-close Smart Life or the Tuya app on local phones and tablets.
2. Temporarily disable this device in LocalTuya and other local integrations.
3. Stop other scripts that poll the device.
4. Confirm that the device is powered and connected to Wi-Fi.
5. Run the analyzer from a network that can reach the device directly.

The official cloud-based Home Assistant Tuya integration can normally remain
enabled because it does not maintain the same direct LAN connection.

## Output

Every run creates two timestamped files in `./logs` by default:

```text
logs/tuya-device-YYYYMMDD-HHMMSS.log
logs/tuya-device-YYYYMMDD-HHMMSS.json
```

- The `.log` file contains the complete console and protocol debug stream.
- The `.json` file contains structured results and successful variants.

Output remains visible in the console while the files are written. A complete
run terminates automatically. Because unsuccessful variants are allowed to
reach their timeouts, a run can take several minutes.

Generated reports are excluded from Git by the included `.gitignore`.

## Understanding the result

The most useful JSON fields are:

| Field | Meaning |
|---|---|
| `target` | Redacted target metadata and identifier lengths |
| `environment` | Python platform and TinyTuya version |
| `probe_settings` | DP list, chunk size, and passive observation duration |
| `tcp_ports` | Reachability of each tested Tuya port |
| `discovery` | Tuya LAN discovery result |
| `probes` | Result of every protocol and query-mode combination |
| `successful_variants` | Variants that returned one or more DPs |

Interpret the report in this order:

1. Check `discovery.response.version` for the advertised protocol.
2. Confirm that a Tuya TCP port is reachable.
3. Inspect the entries under `probes`.
4. Check `successful_variants`.
5. Confirm that a successful variant returned actual `dps` entries.

Typical meanings:

| Result | Likely explanation |
|---|---|
| Port reachable, no variant succeeds | Incorrect credentials, unsupported protocol, or competing local client |
| `Unexpected Payload from Device` | Request or response framing does not match |
| `Check device key or version` | LocalKey or protocol selection is incorrect |
| Standard variant returns DPs | Use that protocol with the normal status query |
| Only `device22` returns DPs | Integration needs the alternative status query |
| Only `3.5-data-dps` returns DPs | Integration needs the alternative 3.5 query payload |
| Only a 3.5 explicit-DP variant returns DPs | Integration must include DP identifiers in its query |
| Only `3.5-updatedps` returns DPs | Integration must request and receive an active DP report |
| Only a chunked variant returns DPs | At least one DP in the larger request is rejected by the device |
| Only `3.5-passive` returns DPs | Device likely reports locally only after state changes |
| Only 3.5 returns DPs | Integration needs genuine 3.5/6699/AES-GCM support |

Manually entering DP numbers cannot fix an incompatible wire protocol. DP
configuration becomes relevant only after messages can be exchanged and
decrypted successfully.

## Troubleshooting

### No console output

Activate the virtual environment and run Python unbuffered:

```bash
python -u tuya_device_analyzer.py \
  --ip <DEVICE_IP> \
  --device-id <DEVICE_ID>
```

The analyzer also enables line-buffered output internally.

### Connection refused

- Confirm that the device is online.
- Check routing, VLAN, firewall, and Wi-Fi client-isolation rules.
- Verify that the computer can reach the device network.

### Timeouts or intermittent disconnects

- Close Smart Life and Tuya apps.
- Disable competing local integrations temporarily.
- Increase `--timeout` or `--pause`.
- Power-cycle the device and wait for it to reconnect.

### No datapoints found

- Compare the discovered protocol with `successful_variants`.
- Verify the LocalKey, especially after re-pairing the device.
- Review the log for authentication, framing, and timeout details.
- Do not assume a successful TCP connection proves compatibility.

### Expected datapoints are missing

Some devices report certain DPs only while a related feature or operating state
is active. A second read-only run in another device state may reveal them.

## Scope and limitations

- The tool diagnoses direct Tuya LAN communication.
- It does not test Tuya IoT Cloud credentials.
- It does not discover or extract a LocalKey.
- It does not configure Home Assistant.
- It does not guarantee that an integration supports the detected protocol.
- Behavior can differ between firmware versions of the same product.

## Related projects

- [TinyTuya](https://github.com/jasonacox/tinytuya)
- [LocalTuya](https://github.com/rospogrigio/localtuya)
- [Home Assistant Tuya integration](https://www.home-assistant.io/integrations/tuya/)

## Contributing

Issues and pull requests are welcome. Before sharing reports, review them and
remove any information you do not want to publish. Never include LocalKeys,
access tokens, unredacted Device IDs, or personal network details in issues.

## License

No license has been selected yet. Until a license file is added, normal
copyright rules apply.
