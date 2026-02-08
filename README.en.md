# smb-slowdiag

Troubleshooting script for SMB latency issues based on `tshark`.

Japanese README: `README.md`

## Features

- metadata/decrypt mode
- SMB/TCP latency and anomaly signal analysis
- RTT aggregation (overall / by direction / by stream)
- SMB session/channel aggregation (`smb2.sesid` + `tcp.stream`)
- Recommended next actions with explicit criteria and threshold status
- Report language switch (`--lang ja|en`)

## Requirements

- Python 3.9+
- `tshark` (Wireshark CLI)

## Usage

```bash
python3 smb_slowdiag.py -r capture.pcapng -o out
```

```bash
python3 smb_slowdiag.py -r capture.pcapng \
  --client-ip 192.168.1.10 --server-ip 192.168.1.20 \
  --interval 30 --max-slow-ops 20 --lang en -o out
```

```bash
python3 smb_slowdiag.py -r encrypted.pcap \
  --smb-key-file smb_keys_example.csv -o out
```

## Key File Format

`session_id,session_key,server2client,client2server`

- `session_id`: 16-digit hex (8 bytes)
- `session_key`: hex

## Output Files

- `summary.md`
- `timeline.csv`
- `top_slow_ops.csv`
- `ntstatus_counts.csv`
- `io_size_latency.csv`
- `rtt_summary.csv`
- `rtt_by_stream.csv`
- `smb_session_summary.csv`
- `smb_channel_summary.csv`
- `tshark_iostat.txt`
- `tshark_smb2_srt.txt`
