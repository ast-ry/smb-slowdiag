# smb-slowdiag

`tshark` ベースで SMB 通信の遅延トラブルシューティングを行うスクリプトです。

English README: `README.en.md`

## Features

- metadata/decrypt mode
- SMB/TCP の遅延・異常シグナル分析
- RTT 集計（全体/方向別/stream別）
- SMB セッション/チャネル集計（`smb2.sesid` + `tcp.stream`）
- 推奨アクション（判定基準・閾値判定付き）
- レポート言語切替（`--lang ja|en`）

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

- `-r, --pcap <path>`: 入力 `pcap/pcapng`（必須）
- `-o, --outdir <dir>`: 出力ディレクトリ（デフォルト: `smb_diag_out`）
- `--client-ip <ip>`: SMBクライアントIP
- `--server-ip <ip>`: SMBサーバーIP
- `--interval <sec>`: 時系列バケット秒数（デフォルト: `1`、最小 `1`）
- `--tshark <path>`: `tshark` 実行ファイルパス（デフォルト: `tshark`）
- `--smb-key-file <csv>`: 復号キーCSV（指定時 `decrypt mode`）
- `--max-slow-ops <n>`: `top_slow_ops.csv` の最大行数（デフォルト: `30`）
- `--lang {ja,en}`: `summary.md` の言語（デフォルト: `ja`）
- `-h, --help`: ヘルプ表示

補足:
- フィルタに `client/server` IP を適用するのは **両方指定した場合のみ** です。
- `--smb-key-file` 未指定時は `metadata mode` で解析します。

## Key File Format

`session_id,session_key,server2client,client2server`

- `session_id`: 16桁hex（8 bytes）
- `session_key`: hex（偶数桁）
- `server2client`, `client2server`: 任意（未使用なら空欄可）
- 先頭 `#` 行はコメントとして無視

## Output Files

- `summary.md`: 総合レポート（所見、推奨アクション、SMB/RTT/マルチチャネル要約）
- `timeline.csv`: 時系列バケット集計
  - 主列: `bucket_start,frames,bytes,retransmissions,dup_acks,zero_window,window_full,smb_req,smb_rsp,avg_smb_time_ms`
- `top_slow_ops.csv`: 遅いSMBオペ上位
  - 主列: `cmd,cmd_name,msg_id,latency_ms,io_size_bytes,src,dst,filename`
- `ntstatus_counts.csv`: NTSTATUS件数
- `io_size_latency.csv`: I/Oサイズバケット別遅延
- `rtt_summary.csv`: RTT要約（全体/方向別）
- `rtt_by_stream.csv`: `tcp.stream` 別RTT統計
- `smb_session_summary.csv`: `smb2.sesid` 別集計（stream数、遅延、非成功ステータスなど）
- `smb_channel_summary.csv`: `smb2.sesid + tcp.stream` 別集計（遅延 + TCP異常）
- `tshark_iostat.txt`: `tshark -z io,stat` 生出力
- `tshark_smb2_srt.txt`: `tshark -z smb2,srt` 生出力
- `run_meta.txt`: 実行メタ情報（mode/filter/rows/keys_loaded）
