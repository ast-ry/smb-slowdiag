# smb-slowdiag

Troubleshooting script for SMB latency issues based on `tshark`.

Japanese README: `README.ja.md`

## Features

- no-key/key-assisted-decrypt mode
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

## Options

- `-r, --pcap <path>`: Input `pcap/pcapng` (required)
- `-o, --outdir <dir>`: Output directory (default: `smb_diag_out`)
- `--client-ip <ip>`: SMB client IP
- `--server-ip <ip>`: SMB server IP
- `--interval <sec>`: Timeline bucket size in seconds (default: `1`, minimum `1`)
- `--tshark <path>`: `tshark` executable path (default: `tshark`)
- `--smb-key-file <csv>`: SMB decryption key CSV (`key-assisted-decrypt mode` when provided)
- `--max-slow-ops <n>`: Max rows in `top_slow_ops.csv` (default: `30`)
- `--lang {ja,en}`: `summary.md` language (default: `ja`)
- `-h, --help`: Show help

Notes:
- Client/server IP filtering is applied **only when both** `--client-ip` and `--server-ip` are provided.
- Without `--smb-key-file`, analysis runs in `no-key mode`.

## Key File Format

`session_id,session_key,server2client,client2server`

- `session_id`: 16-digit hex (8 bytes)
- `session_key`: hex (even number of digits)
- `server2client`, `client2server`: optional (can be empty)
- Lines starting with `#` are treated as comments

## Output Files

- `summary.md`: Consolidated report (findings, recommended actions with threshold source/confidence/evidence, SMB/RTT/multichannel summary)
- `timeline.csv`: Time-bucketed counters
  - Main columns: `bucket_start,frames,bytes,retransmissions,dup_acks,zero_window,window_full,smb_req,smb_rsp,avg_smb_time_ms`
- `top_slow_ops.csv`: Top slow SMB operations
  - Main columns: `cmd,cmd_name,msg_id,latency_ms,io_size_bytes,src,dst,filename`
- `ntstatus_counts.csv`: NTSTATUS counts
- `io_size_latency.csv`: Latency by I/O size bucket
- `rtt_summary.csv`: RTT summary (overall / by direction)
- `rtt_by_stream.csv`: RTT stats by `tcp.stream`
- `stream_diagnosis.csv`: Per-`tcp.stream` diagnostics (score, triggered action IDs, SMB/RTT/TCP anomaly stats)
- `connection_setup_summary.csv`: Connection setup phase stats (`NEGOTIATE/SESSION_SETUP/TREE_CONNECT`)
- `smb_session_summary.csv`: Aggregation by `smb2.sesid` (stream count, latency, non-success status)
- `smb_channel_summary.csv`: Aggregation by `smb2.sesid + tcp.stream` (latency + TCP anomalies)
- `tshark_iostat.txt`: Raw output of `tshark -z io,stat`
- `tshark_smb2_srt.txt`: Raw output of `tshark -z smb2,srt`
- `run_meta.txt`: Run metadata (`mode/filter/rows/keys_loaded`)
