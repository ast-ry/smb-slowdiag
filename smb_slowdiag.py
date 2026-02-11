#!/usr/bin/env python3
"""
SMB slow access diagnostics from pcap using tshark.

Modes:
- no-key mode: SMB decryption keys are not provided
- key-assisted decrypt mode: SMB session keys are provided and tshark attempts decryption
"""

from __future__ import annotations

import argparse
import csv
import io
import os
import re
import shutil
import statistics
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Iterable


@dataclass
class Config:
    pcap: str
    outdir: str
    client_ip: str | None
    server_ip: str | None
    interval: int
    tshark: str
    smb_key_file: str | None
    max_slow_ops: int
    lang: str


SMB2_CMD_NAMES = {
    "0": "NEGOTIATE",
    "1": "SESSION_SETUP",
    "2": "LOGOFF",
    "3": "TREE_CONNECT",
    "4": "TREE_DISCONNECT",
    "5": "CREATE",
    "6": "CLOSE",
    "7": "FLUSH",
    "8": "READ",
    "9": "WRITE",
    "10": "LOCK",
    "11": "IOCTL",
    "12": "CANCEL",
    "13": "ECHO",
    "14": "QUERY_DIRECTORY",
    "15": "CHANGE_NOTIFY",
    "16": "QUERY_INFO",
    "17": "SET_INFO",
    "18": "OPLOCK_BREAK",
}
SMB2_CMD_BY_NAME = {v.upper(): k for k, v in SMB2_CMD_NAMES.items()}


SMB_DIALECT_NAMES = {
    "0x0202": "SMB 2.0.2",
    "0x0210": "SMB 2.1",
    "0x0300": "SMB 3.0",
    "0x0302": "SMB 3.0.2",
    "0x0311": "SMB 3.1.1",
    "0x02ff": "SMB 2.x Wildcard",
}


NTSTATUS_HINTS = {
    "0x00000000": "STATUS_SUCCESS",
    "0xc0000016": "STATUS_MORE_PROCESSING_REQUIRED",
    "0xc000006d": "STATUS_LOGON_FAILURE",
    "0xc0000022": "STATUS_ACCESS_DENIED",
    "0xc0000034": "STATUS_OBJECT_NAME_NOT_FOUND",
    "0xc0000035": "STATUS_OBJECT_NAME_COLLISION",
    "0xc00000bb": "STATUS_NOT_SUPPORTED",
}


TROUBLESHOOT_REFS = {
    "ms_smb_troubleshoot": "https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/troubleshooting-smb",
    "ms_slow_smb_transfer": "https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/slow-smb-file-transfer",
    "ms_erref": "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55",
    "ms_smb2_credit": "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/fba3123b-f566-4d8f-9715-0f529e856d25",
    "wireshark_tcp_dfref": "https://www.wireshark.org/docs/dfref/t/tcp.html",
}


def parse_args() -> Config:
    parser = argparse.ArgumentParser(
        description="Diagnose slow SMB traffic using tshark (no-key/key-assisted-decrypt mode)."
    )
    parser.add_argument("-r", "--pcap", required=True, help="Input pcap/pcapng file")
    parser.add_argument("-o", "--outdir", default="smb_diag_out", help="Output directory")
    parser.add_argument("--client-ip", help="SMB client IP address")
    parser.add_argument("--server-ip", help="SMB server IP address")
    parser.add_argument(
        "--interval", type=int, default=1, help="Time bucket for timeline in seconds"
    )
    parser.add_argument("--tshark", default="tshark", help="Path to tshark binary")
    parser.add_argument(
        "--smb-key-file",
        help="CSV file for SMB decryption keys: session_id,session_key,server2client,client2server",
    )
    parser.add_argument(
        "--max-slow-ops", type=int, default=30, help="How many slow operations to output"
    )
    parser.add_argument(
        "--lang",
        choices=["ja", "en"],
        default="ja",
        help="Report language (ja or en)",
    )
    args = parser.parse_args()

    return Config(
        pcap=args.pcap,
        outdir=args.outdir,
        client_ip=args.client_ip,
        server_ip=args.server_ip,
        interval=max(1, args.interval),
        tshark=args.tshark,
        smb_key_file=args.smb_key_file,
        max_slow_ops=max(1, args.max_slow_ops),
        lang=args.lang,
    )


def run_cmd(cmd: list[str]) -> str:
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if proc.returncode != 0:
        raise RuntimeError(
            f"Command failed ({proc.returncode}): {' '.join(cmd)}\n{proc.stderr.strip()}"
        )
    return proc.stdout


def check_prereq(cfg: Config) -> None:
    if not os.path.isfile(cfg.pcap):
        raise FileNotFoundError(f"pcap not found: {cfg.pcap}")
    tshark_bin = shutil.which(cfg.tshark) if os.path.sep not in cfg.tshark else cfg.tshark
    if not tshark_bin:
        raise FileNotFoundError(f"tshark not found: {cfg.tshark}")
    run_cmd([cfg.tshark, "-v"])


def read_key_file(path: str) -> list[tuple[str, str, str, str]]:
    keys = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row or row[0].strip().startswith("#"):
                continue
            if len(row) < 2:
                continue
            sid = row[0].strip()
            skey = row[1].strip()
            s2c = row[2].strip() if len(row) > 2 else ""
            c2s = row[3].strip() if len(row) > 3 else ""
            if sid and skey:
                keys.append(
                    (
                        normalize_session_id(sid),
                        normalize_hex_key(skey, "session_key"),
                        normalize_hex_key(s2c, "server2client") if s2c else "",
                        normalize_hex_key(c2s, "client2server") if c2s else "",
                    )
                )
    return keys


def normalize_session_id(raw: str) -> str:
    sid = raw.strip().lower()
    if sid.startswith("0x"):
        sid = sid[2:]
    if not re.fullmatch(r"[0-9a-f]+", sid or ""):
        raise ValueError(f"invalid session_id (hex only): {raw}")
    if len(sid) != 16:
        raise ValueError(
            f"invalid session_id length: {raw} (expected 16 hex chars / 8 bytes)"
        )
    return sid


def normalize_hex_key(raw: str, field_name: str) -> str:
    key = raw.strip().lower().replace(":", "").replace("-", "")
    if key.startswith("0x"):
        key = key[2:]
    if not key:
        return ""
    if not re.fullmatch(r"[0-9a-f]+", key):
        raise ValueError(f"invalid {field_name} (hex only): {raw}")
    if len(key) % 2 != 0:
        raise ValueError(f"invalid {field_name} length (must be even hex chars): {raw}")
    return key


def make_uat_smb2_seskey_list(keys: Iterable[tuple[str, str, str, str]]) -> str:
    entries = []
    for sid, skey, s2c, c2s in keys:
        entries.append(f"{sid},{skey},{s2c},{c2s}")
    return ";".join(entries)


def base_filter(cfg: Config) -> str:
    filt = "(tcp.port == 445)"
    if cfg.client_ip and cfg.server_ip:
        filt += (
            f" && ((ip.src == {cfg.client_ip} && ip.dst == {cfg.server_ip})"
            f" || (ip.src == {cfg.server_ip} && ip.dst == {cfg.client_ip}))"
        )
    return filt


def tshark_fields(
    cfg: Config, fields: list[str], display_filter: str, extra_opts: list[str] | None = None
) -> list[dict[str, str]]:
    cmd = [
        cfg.tshark,
        "-r",
        cfg.pcap,
        "-Y",
        display_filter,
        "-T",
        "fields",
        "-E",
        "header=y",
        "-E",
        "separator=,",
        "-E",
        "quote=d",
        "-E",
        "occurrence=f",
    ]
    for f in fields:
        cmd.extend(["-e", f])
    if extra_opts:
        cmd.extend(extra_opts)

    out = run_cmd(cmd)
    buf = io.StringIO(out)
    reader = csv.DictReader(buf)
    return list(reader)


def tshark_io_stat(cfg: Config, filter_expr: str) -> str:
    z = f"io,stat,{cfg.interval},COUNT(frame)frames,SUM(frame.len)bytes,AVG(tcp.time_delta)avg_delta,{filter_expr}"
    cmd = [cfg.tshark, "-r", cfg.pcap, "-q", "-z", z]
    return run_cmd(cmd)


def tshark_smb2_srt(cfg: Config, filter_expr: str, extra_opts: list[str] | None = None) -> str:
    cmd = [cfg.tshark, "-r", cfg.pcap, "-Y", filter_expr, "-q", "-z", "smb2,srt"]
    if extra_opts:
        cmd.extend(extra_opts)
    return run_cmd(cmd)


def summarize_latency(ms_values: list[float]) -> dict[str, float]:
    if not ms_values:
        return {"count": 0, "avg_ms": 0.0, "p50_ms": 0.0, "p95_ms": 0.0, "max_ms": 0.0}
    sorted_vals = sorted(ms_values)

    def percentile(p: float) -> float:
        if len(sorted_vals) == 1:
            return sorted_vals[0]
        pos = (len(sorted_vals) - 1) * p
        lo = int(pos)
        hi = min(lo + 1, len(sorted_vals) - 1)
        frac = pos - lo
        return sorted_vals[lo] * (1.0 - frac) + sorted_vals[hi] * frac

    p50 = percentile(0.50)
    p95 = percentile(0.95)
    return {
        "count": len(ms_values),
        "avg_ms": statistics.fmean(ms_values),
        "p50_ms": p50,
        "p95_ms": p95,
        "max_ms": max(ms_values),
    }


def size_bucket(size: int) -> str:
    if size <= 0:
        return "unknown"
    if size <= 4096:
        return "0-4KiB"
    if size <= 16384:
        return "4-16KiB"
    if size <= 65536:
        return "16-64KiB"
    if size <= 262144:
        return "64-256KiB"
    if size <= 1048576:
        return "256KiB-1MiB"
    return "1MiB+"


def write_csv(path: str, rows: list[dict[str, object]], header: list[str]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=header)
        w.writeheader()
        for r in rows:
            w.writerow(r)


def to_float(v: str, default: float = 0.0) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def to_int(v: str, default: int = 0) -> int:
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return default


def to_bool(v: str) -> bool:
    s = (v or "").strip().lower()
    if not s:
        return False
    tokens = [t.strip() for t in s.split(",") if t.strip()]
    if not tokens:
        tokens = [s]
    for t in tokens:
        if t in {"1", "true", "yes"}:
            return True
        try:
            if int(t, 0) != 0:
                return True
        except ValueError:
            pass
    return False


def normalize_smb2_cmd(v: str) -> str:
    s = (v or "").strip()
    if not s:
        return ""
    token = s.split(",")[0].strip()
    if not token:
        return ""
    try:
        return str(int(token, 0))
    except ValueError:
        pass
    m = re.search(r"0x([0-9a-fA-F]+)", token)
    if m:
        return str(int(m.group(1), 16))
    upper = re.sub(r"[^A-Z0-9_]", "_", token.upper())
    upper = re.sub(r"_+", "_", upper).strip("_")
    if upper in SMB2_CMD_BY_NAME:
        return SMB2_CMD_BY_NAME[upper]
    return ""


def yes_no(v: bool, lang: str = "en") -> str:
    if lang == "ja":
        return "はい" if v else "いいえ"
    return "Yes" if v else "No"


def format_links(value: str) -> str:
    urls = [u.strip() for u in str(value or "").split("|") if u.strip()]
    if not urls:
        return ""
    parts = []
    for i, u in enumerate(urls, start=1):
        parts.append(f"[link{i}]({u}) <{u}>")
    return " | ".join(parts)


def build_recommended_actions(
    lang: str,
    total_frames: int,
    retrans_count: int,
    dup_ack_count: int,
    zero_window_count: int,
    window_full_count: int,
    smb_latency: dict[str, float],
    rtt_overall: dict[str, float],
    status_counts: Counter,
    credit_pressure_count: int,
    outstanding_peak: int,
) -> list[dict[str, str]]:
    actions = []
    frame_base = max(1, total_frames)
    retrans_pct = (retrans_count / frame_base) * 100.0
    dupack_pct = (dup_ack_count / frame_base) * 100.0
    zero_pct = (zero_window_count / frame_base) * 100.0
    winfull_pct = (window_full_count / frame_base) * 100.0
    smb_p95 = smb_latency.get("p95_ms", 0.0)
    rtt_p95 = rtt_overall.get("p95_ms", 0.0)

    ja = lang == "ja"
    t1 = retrans_count >= 3 or retrans_pct >= 0.10 or dup_ack_count >= 10 or dupack_pct >= 0.20
    actions.append(
        {
            "id": "1",
            "status": ("Triggered" if t1 else "Monitor") if not ja else ("要対応" if t1 else "監視"),
            "threshold": ("Exceeded" if t1 else "Not exceeded")
            if not ja
            else ("超過" if t1 else "未超過"),
            "title": "Network quality (loss / reordering)"
            if not ja
            else "ネットワーク品質（ロス/順序入れ替わり）",
            "trigger": (
                f"retrans={retrans_count} ({retrans_pct:.2f}%), dup_ack={dup_ack_count} ({dupack_pct:.2f}%)"
            ),
            "criteria": "retrans_count >= 3 OR retrans_pct >= 0.10% OR dup_ack_count >= 10 OR dup_ack_pct >= 0.20%",
            "next": (
                "Collect same-time captures at both endpoints; validate NIC errors/drops; "
                "check MTU mismatch and path quality with iperf/ping."
            )
            if not ja
            else (
                "両端で同時刻キャプチャを取得し、NICのエラー/ドロップを確認。"
                "MTU不一致と経路品質を iperf/ping で確認。"
            ),
            "refs": f"{TROUBLESHOOT_REFS['ms_slow_smb_transfer']} | {TROUBLESHOOT_REFS['wireshark_tcp_dfref']}",
            "source_type": "case-calibrated",
            "confidence": "medium",
            "evidence": f"{TROUBLESHOOT_REFS['ms_slow_smb_transfer']} | {TROUBLESHOOT_REFS['wireshark_tcp_dfref']}",
        }
    )

    t2 = zero_window_count >= 3 or zero_pct >= 0.05 or window_full_count >= 10 or winfull_pct >= 0.20
    actions.append(
        {
            "id": "2",
            "status": ("Triggered" if t2 else "Monitor") if not ja else ("要対応" if t2 else "監視"),
            "threshold": ("Exceeded" if t2 else "Not exceeded")
            if not ja
            else ("超過" if t2 else "未超過"),
            "title": "Receiver backpressure (socket/window bottleneck)"
            if not ja
            else "受信側バックプレッシャー（ソケット/ウィンドウ）",
            "trigger": (
                f"zero_window={zero_window_count} ({zero_pct:.2f}%), window_full={window_full_count} ({winfull_pct:.2f}%)"
            ),
            "criteria": "zero_window_count >= 3 OR zero_window_pct >= 0.05% OR window_full_count >= 10 OR window_full_pct >= 0.20%",
            "next": (
                "Check endpoint CPU/memory pressure and socket buffers; review application throughput limits; "
                "verify if a single flow is saturating receive processing."
            )
            if not ja
            else (
                "端点CPU/メモリ負荷とソケットバッファを確認。"
                "アプリ側スループット制約と単一フロー過負荷を確認。"
            ),
            "refs": f"{TROUBLESHOOT_REFS['ms_slow_smb_transfer']} | {TROUBLESHOOT_REFS['wireshark_tcp_dfref']}",
            "source_type": "case-calibrated",
            "confidence": "medium",
            "evidence": f"{TROUBLESHOOT_REFS['ms_slow_smb_transfer']} | {TROUBLESHOOT_REFS['wireshark_tcp_dfref']}",
        }
    )

    t3 = (
        smb_p95 >= 100.0
        and (rtt_overall.get("count", 0) == 0 or rtt_p95 <= 20.0)
        and retrans_count < 3
    )
    actions.append(
        {
            "id": "3",
            "status": ("Triggered" if t3 else "Monitor") if not ja else ("要対応" if t3 else "監視"),
            "threshold": ("Exceeded" if t3 else "Not exceeded")
            if not ja
            else ("超過" if t3 else "未超過"),
            "title": "Server/storage-side processing delay"
            if not ja
            else "サーバー/ストレージ側の処理遅延",
            "trigger": f"smb_p95={smb_p95:.3f}ms, rtt_p95={rtt_p95:.3f}ms, retrans={retrans_count}",
            "criteria": "smb_p95_ms >= 100 AND retrans_count < 3 AND (rtt_p95_ms <= 20 OR no_rtt_samples)",
            "next": (
                "Correlate with server disk latency, AV scanning, and file-lock contention; "
                "check server event logs and storage queue depth in the same time window."
            )
            if not ja
            else (
                "サーバーのディスク遅延、AVスキャン、ファイルロック競合を同時刻で突合。"
                "イベントログとストレージキュー深度を確認。"
            ),
            "refs": TROUBLESHOOT_REFS["ms_smb_troubleshoot"],
            "source_type": "case-calibrated",
            "confidence": "medium",
            "evidence": TROUBLESHOOT_REFS["ms_smb_troubleshoot"],
        }
    )

    total_status = sum(status_counts.values())
    auth_acl_hits = (
        status_counts.get("0xc000006d", 0)
        + status_counts.get("0xc0000022", 0)
        + status_counts.get("0xc0000034", 0)
    )
    auth_acl_pct = (auth_acl_hits / max(1, total_status)) * 100.0
    t4 = auth_acl_hits >= 3 or auth_acl_pct >= 5.0
    actions.append(
        {
            "id": "4",
            "status": ("Triggered" if t4 else "Monitor") if not ja else ("要対応" if t4 else "監視"),
            "threshold": ("Exceeded" if t4 else "Not exceeded")
            if not ja
            else ("超過" if t4 else "未超過"),
            "title": "Authentication/authorization/path errors"
            if not ja
            else "認証/認可/パス関連エラー",
            "trigger": f"auth_acl_related={auth_acl_hits}/{total_status} ({auth_acl_pct:.1f}%)",
            "criteria": "count(0xc000006d,0xc0000022,0xc0000034) >= 3 OR ratio >= 5%",
            "next": (
                "Validate credentials, SPN/Kerberos/NTLM fallback, and share/file ACLs; "
                "cross-check server security logs for matching timestamps."
            )
            if not ja
            else (
                "資格情報、SPN/Kerberos/NTLMフォールバック、共有/ファイルACLを確認。"
                "同時刻のサーバーセキュリティログを突合。"
            ),
            "refs": f"{TROUBLESHOOT_REFS['ms_smb_troubleshoot']} | {TROUBLESHOOT_REFS['ms_erref']}",
            "source_type": "official+case-calibrated",
            "confidence": "high",
            "evidence": f"{TROUBLESHOOT_REFS['ms_smb_troubleshoot']} | {TROUBLESHOOT_REFS['ms_erref']}",
        }
    )

    t5 = credit_pressure_count >= 5
    actions.append(
        {
            "id": "5",
            "status": ("Triggered" if t5 else "Monitor") if not ja else ("要対応" if t5 else "監視"),
            "threshold": ("Exceeded" if t5 else "Not exceeded")
            if not ja
            else ("超過" if t5 else "未超過"),
            "title": "SMB credit/concurrency bottleneck"
            if not ja
            else "SMBクレジット/並列性ボトルネック",
            "trigger": f"credit_pressure_events={credit_pressure_count}, outstanding_peak={outstanding_peak}",
            "criteria": "credit_pressure_count >= 5 (credits.requested > credits.granted)",
            "next": (
                "Increase parallel I/O depth and verify client/server credit behavior; "
                "review workload pattern if large transfer is serialized by low outstanding requests."
            )
            if not ja
            else (
                "並列I/O深度を増やし、クライアント/サーバーのcredit挙動を確認。"
                "outstandingが低く大容量転送が直列化していないか確認。"
            ),
            "refs": f"{TROUBLESHOOT_REFS['ms_smb2_credit']} | {TROUBLESHOOT_REFS['ms_smb_troubleshoot']}",
            "source_type": "official+case-calibrated",
            "confidence": "medium",
            "evidence": f"{TROUBLESHOOT_REFS['ms_smb2_credit']} | {TROUBLESHOOT_REFS['ms_smb_troubleshoot']}",
        }
    )
    return actions


def analyze_connection_setup(
    rows_sorted: list[dict[str, str]]
) -> tuple[list[dict[str, object]], dict[str, object]]:
    by_session: dict[str, dict[str, object]] = defaultdict(
        lambda: {
            "first_negotiate_req_ts": None,
            "first_session_setup_rsp_ts": None,
            "first_tree_connect_rsp_ts": None,
            "negotiate_rsp_ms": [],
            "session_setup_rsp_ms": [],
            "tree_connect_rsp_ms": [],
            "session_setup_non_success": 0,
            "session_setup_more_processing": 0,
            "session_setup_success": 0,
            "auth_failure_like": 0,
        }
    )
    by_stream: dict[str, dict[str, float | None]] = defaultdict(
        lambda: {"first_negotiate_req_ts": None, "first_setup_rsp_ts": None}
    )

    for r in rows_sorted:
        sesid = r.get("smb2.sesid", "")
        stream = r.get("tcp.stream", "")
        if not sesid:
            # keep collecting stream-level setup timing for fallback
            cmd = normalize_smb2_cmd(r.get("smb2.cmd", ""))
            is_response = to_bool(r.get("smb2.flags.response", "0"))
            ts = to_float(r.get("frame.time_epoch", "0"))
            if stream:
                st = by_stream[stream]
                if cmd == "0" and not is_response and st["first_negotiate_req_ts"] is None:
                    st["first_negotiate_req_ts"] = ts
                if cmd in {"1", "3"} and is_response and st["first_setup_rsp_ts"] is None:
                    st["first_setup_rsp_ts"] = ts
            continue
        cmd = normalize_smb2_cmd(r.get("smb2.cmd", ""))
        is_response = to_bool(r.get("smb2.flags.response", "0"))
        ts = to_float(r.get("frame.time_epoch", "0"))
        t_ms = to_float(r.get("smb2.time", "0")) * 1000.0
        nt = (r.get("smb2.nt_status", "") or "").lower()
        sess = by_session[sesid]
        if stream:
            st = by_stream[stream]
            if cmd == "0" and not is_response and st["first_negotiate_req_ts"] is None:
                st["first_negotiate_req_ts"] = ts
            if cmd in {"1", "3"} and is_response and st["first_setup_rsp_ts"] is None:
                st["first_setup_rsp_ts"] = ts

        if cmd == "0" and not is_response and sess["first_negotiate_req_ts"] is None:
            sess["first_negotiate_req_ts"] = ts
        if cmd == "0" and is_response and t_ms > 0:
            sess["negotiate_rsp_ms"].append(t_ms)
        if cmd == "1" and is_response:
            if sess["first_session_setup_rsp_ts"] is None:
                sess["first_session_setup_rsp_ts"] = ts
            if t_ms > 0:
                sess["session_setup_rsp_ms"].append(t_ms)
            if nt == "0x00000000":
                sess["session_setup_success"] += 1
            elif nt == "0xc0000016":
                sess["session_setup_more_processing"] += 1
            else:
                sess["session_setup_non_success"] += 1
                if nt in {"0xc000006d", "0xc0000022", "0xc0000034"}:
                    sess["auth_failure_like"] += 1
        if cmd == "3" and is_response:
            if sess["first_tree_connect_rsp_ts"] is None:
                sess["first_tree_connect_rsp_ts"] = ts
            if t_ms > 0:
                sess["tree_connect_rsp_ms"].append(t_ms)

    rows = []
    setup_windows = []
    setup_rsp_all = []
    setup_rsp_fail = 0
    setup_rsp_success = 0
    auth_fail_like = 0
    sessions_with_setup = 0
    for sesid in sorted(by_session.keys()):
        s = by_session[sesid]
        n = summarize_latency(s["negotiate_rsp_ms"])
        ss = summarize_latency(s["session_setup_rsp_ms"])
        tc = summarize_latency(s["tree_connect_rsp_ms"])
        start = s["first_negotiate_req_ts"]
        end = s["first_tree_connect_rsp_ts"] or s["first_session_setup_rsp_ts"]
        setup_ms = 0.0
        if start and end and end >= start:
            setup_ms = (end - start) * 1000.0
            setup_windows.append(setup_ms)
        if ss["count"] > 0:
            sessions_with_setup += 1
            setup_rsp_all.extend(s["session_setup_rsp_ms"])
        setup_rsp_fail += int(s["session_setup_non_success"])
        setup_rsp_success += int(s["session_setup_success"])
        auth_fail_like += int(s["auth_failure_like"])
        rows.append(
            {
                "smb_session_id": sesid,
                "setup_window_ms": f"{setup_ms:.3f}" if setup_ms > 0 else "",
                "negotiate_rsp_count": int(n["count"]),
                "negotiate_p95_ms": f"{n['p95_ms']:.3f}",
                "session_setup_rsp_count": int(ss["count"]),
                "session_setup_p95_ms": f"{ss['p95_ms']:.3f}",
                "session_setup_success": int(s["session_setup_success"]),
                "session_setup_non_success": int(s["session_setup_non_success"]),
                "session_setup_more_processing": int(s["session_setup_more_processing"]),
                "auth_failure_like": int(s["auth_failure_like"]),
                "tree_connect_rsp_count": int(tc["count"]),
                "tree_connect_p95_ms": f"{tc['p95_ms']:.3f}",
            }
        )

    stream_setup_windows = []
    for st in by_stream.values():
        start = st["first_negotiate_req_ts"]
        end = st["first_setup_rsp_ts"]
        if start and end and end >= start:
            stream_setup_windows.append((end - start) * 1000.0)

    setup_window_source = "session"
    selected_setup_windows = setup_windows
    if not selected_setup_windows and stream_setup_windows:
        setup_window_source = "stream_fallback"
        selected_setup_windows = stream_setup_windows

    setup_window_stats = summarize_latency(selected_setup_windows)
    setup_rsp_stats = summarize_latency(setup_rsp_all)
    summary = {
        "sessions_with_setup": sessions_with_setup,
        "setup_window_p95_ms": setup_window_stats["p95_ms"],
        "setup_window_avg_ms": setup_window_stats["avg_ms"],
        "setup_window_count": int(setup_window_stats["count"]),
        "setup_window_source": setup_window_source,
        "session_setup_rsp_count": int(setup_rsp_stats["count"]),
        "session_setup_p95_ms": setup_rsp_stats["p95_ms"],
        "session_setup_avg_ms": setup_rsp_stats["avg_ms"],
        "session_setup_non_success": setup_rsp_fail,
        "session_setup_success": setup_rsp_success,
        "auth_failure_like": auth_fail_like,
    }
    return rows, summary


def detect_mode(cfg: Config) -> tuple[str, list[str], list[tuple[str, str, str, str]]]:
    extra_opts: list[str] = []
    keys: list[tuple[str, str, str, str]] = []
    mode = "no-key"
    if cfg.smb_key_file:
        if not os.path.isfile(cfg.smb_key_file):
            raise FileNotFoundError(f"smb key file not found: {cfg.smb_key_file}")
        keys = read_key_file(cfg.smb_key_file)
        if keys:
            mode = "key-assisted-decrypt"
            uat = make_uat_smb2_seskey_list(keys)
            extra_opts = ["-o", f"uat:smb2_seskey_list:{uat}"]
    return mode, extra_opts, keys


def timeline_from_rows(
    rows: list[dict[str, str]], interval: int, client_ip: str | None, server_ip: str | None
) -> list[dict[str, object]]:
    buckets: dict[int, dict[str, object]] = defaultdict(
        lambda: {
            "bucket_start": 0,
            "frames": 0,
            "bytes": 0,
            "retransmissions": 0,
            "dup_acks": 0,
            "zero_window": 0,
            "window_full": 0,
            "smb_req": 0,
            "smb_rsp": 0,
            "avg_smb_time_ms": 0.0,
        }
    )
    smb_times = defaultdict(list)
    for r in rows:
        ts = to_float(r.get("frame.time_epoch", "0"))
        bucket = int(ts // interval) * interval
        b = buckets[bucket]
        b["bucket_start"] = bucket
        b["frames"] = to_int(b["frames"]) + 1
        b["bytes"] = to_int(b["bytes"]) + to_int(r.get("frame.len", "0"))
        if r.get("tcp.analysis.retransmission"):
            b["retransmissions"] = to_int(b["retransmissions"]) + 1
        if r.get("tcp.analysis.duplicate_ack"):
            b["dup_acks"] = to_int(b["dup_acks"]) + 1
        if r.get("tcp.analysis.zero_window"):
            b["zero_window"] = to_int(b["zero_window"]) + 1
        if r.get("tcp.analysis.window_full"):
            b["window_full"] = to_int(b["window_full"]) + 1

        src = r.get("ip.src", "")
        dst = r.get("ip.dst", "")
        is_req = not to_bool(r.get("smb2.flags.response", "0"))
        if client_ip and server_ip:
            if src == client_ip and dst == server_ip and is_req:
                b["smb_req"] = to_int(b["smb_req"]) + 1
            if src == server_ip and dst == client_ip and not is_req:
                b["smb_rsp"] = to_int(b["smb_rsp"]) + 1
        else:
            if is_req:
                b["smb_req"] = to_int(b["smb_req"]) + 1
            else:
                b["smb_rsp"] = to_int(b["smb_rsp"]) + 1

        smb_time = to_float(r.get("smb2.time", "0"))
        if smb_time > 0:
            smb_times[bucket].append(smb_time * 1000.0)

    out = []
    for k in sorted(buckets.keys()):
        row = buckets[k]
        vals = smb_times.get(k, [])
        row["avg_smb_time_ms"] = round(statistics.fmean(vals), 3) if vals else 0.0
        out.append(row)
    return out


def write_markdown_summary(
    cfg: Config,
    mode: str,
    total_frames: int,
    total_bytes: int,
    smb_latency: dict[str, float],
    status_counts: Counter,
    cmd_latency: dict[str, list[float]],
    credit_pressure_count: int,
    outstanding_peak: int,
    encrypted_payload_frames: int,
    retrans_count: int,
    dup_ack_count: int,
    zero_window_count: int,
    window_full_count: int,
    io_size_stats: dict[str, list[float]],
    smb_props: dict[str, object],
    rtt_overall: dict[str, float],
    rtt_by_direction: dict[str, dict[str, float]],
    multichannel_sessions: list[dict[str, object]],
    setup_summary: dict[str, object],
    stream_diagnosis_rows: list[dict[str, object]],
    out_path: str,
) -> None:
    ja = cfg.lang == "ja"
    actions = build_recommended_actions(
        lang=cfg.lang,
        total_frames=total_frames,
        retrans_count=retrans_count,
        dup_ack_count=dup_ack_count,
        zero_window_count=zero_window_count,
        window_full_count=window_full_count,
        smb_latency=smb_latency,
        rtt_overall=rtt_overall,
        status_counts=status_counts,
        credit_pressure_count=credit_pressure_count,
        outstanding_peak=outstanding_peak,
    )
    triggered_actions = [
        a for a in actions if a.get("status") in (("要対応",) if ja else ("Triggered",))
    ]
    findings = []
    if triggered_actions:
        findings.append(
            (
                "閾値超過の項目があります（"
                + ", ".join(a["id"] for a in triggered_actions)
                + "）。「推奨される次アクション」の要対応項目を優先してください。"
            )
            if ja
            else (
                "Some thresholds were exceeded ("
                + ", ".join(a["id"] for a in triggered_actions)
                + "). Prioritize the Triggered items in Recommended Next Actions."
            )
        )
    if retrans_count > 0 or dup_ack_count > 0:
        findings.append(
            "TCP再送/重複ACKが観測されました。ネットワーク品質または経路混雑の影響を疑ってください。"
            if ja
            else "TCP retransmissions/duplicate ACKs were observed. Suspect network quality issues or path congestion."
        )
    if zero_window_count > 0:
        findings.append(
            "Zero Windowが観測されました。受信側処理遅延やバッファ圧迫の可能性があります。"
            if ja
            else "Zero Window was observed. This may indicate receiver-side processing delay or buffer pressure."
        )
    if credit_pressure_count > 0:
        findings.append(
            "SMB credit不足傾向が見られます。並列I/Oが制限されている可能性があります。"
            if ja
            else "SMB credit pressure was detected. Parallel I/O may be constrained."
        )
    if smb_latency.get("p95_ms", 0.0) > 100 and retrans_count == 0:
        findings.append(
            "SMB応答時間が高い一方で再送が少ないため、サーバー側処理/ストレージ待ちの可能性があります。"
            if ja
            else "SMB latency is high while retransmissions are low, suggesting server-side processing or storage delay."
        )
    if not findings:
        findings.append(
            "顕著な異常パターンは限定的です。時系列のピーク時間帯を重点確認してください。"
            if ja
            else "No dominant anomaly pattern found. Focus on peak time windows in the timeline."
        )

    top_cmd = []
    for cmd, vals in cmd_latency.items():
        s = summarize_latency(vals)
        if s["count"] > 0:
            top_cmd.append((cmd, s))
    top_cmd.sort(key=lambda x: x[1]["p95_ms"], reverse=True)

    with open(out_path, "w", encoding="utf-8") as f:
        f.write("# SMB SlowDiag Summary\n\n" if not ja else "# SMB SlowDiag レポート\n\n")
        f.write(f"- {'Input pcap' if not ja else '入力pcap'}: `{cfg.pcap}`\n")
        f.write(f"- {'Mode' if not ja else 'モード'}: `{mode}`\n")
        f.write(f"- {'Total frames' if not ja else '総フレーム数'}: `{total_frames}`\n")
        f.write(f"- {'Total bytes' if not ja else '総バイト数'}: `{total_bytes}`\n")
        f.write(f"- {'Client IP' if not ja else 'クライアントIP'}: `{cfg.client_ip or 'auto'}`\n")
        f.write(f"- {'Server IP' if not ja else 'サーバーIP'}: `{cfg.server_ip or 'auto'}`\n\n")
        f.write(f"## {'Session/Flow Health' if not ja else 'セッション/フロー健全性'}\n\n")
        f.write(
            f"- {'SMB encrypted payload frames (transform)' if not ja else 'SMB暗号化ペイロードフレーム数(transform)'}: `{encrypted_payload_frames}`\n"
        )
        f.write(
            f"- {'Outstanding SMB requests peak' if not ja else 'SMB未応答リクエストのピーク'}: `{outstanding_peak}`\n"
        )
        f.write(
            f"- {'Credit pressure events (requested > granted)' if not ja else 'Credit圧迫イベント数(requested > granted)'}: `{credit_pressure_count}`\n\n"
        )

        f.write(f"## {'Network Signals' if not ja else 'ネットワークシグナル'}\n\n")
        f.write(
            f"- {'TCP retransmissions' if not ja else 'TCP再送'}: `{retrans_count}` ({(retrans_count / max(1, total_frames)) * 100:.2f}%{' of frames' if not ja else ''})\n"
        )
        f.write(
            f"- {'TCP duplicate ACKs' if not ja else 'TCP重複ACK'}: `{dup_ack_count}` ({(dup_ack_count / max(1, total_frames)) * 100:.2f}%{' of frames' if not ja else ''})\n"
        )
        f.write(
            f"- {'TCP zero window' if not ja else 'TCPゼロウィンドウ'}: `{zero_window_count}` ({(zero_window_count / max(1, total_frames)) * 100:.2f}%{' of frames' if not ja else ''})\n"
        )
        f.write(
            f"- {'TCP window full' if not ja else 'TCPウィンドウフル'}: `{window_full_count}` ({(window_full_count / max(1, total_frames)) * 100:.2f}%{' of frames' if not ja else ''})\n\n"
        )

        f.write(f"## {'Network RTT' if not ja else 'ネットワークRTT'}\n\n")
        if rtt_overall["count"] > 0:
            f.write(
                "- Metric: `tcp.analysis.ack_rtt` converted to ms\n"
                if not ja
                else "- 指標: `tcp.analysis.ack_rtt` を ms に換算\n"
            )
            f.write(
                f"- Overall: count={int(rtt_overall['count'])}, mean={rtt_overall['avg_ms']:.3f} ms, median(P50)={rtt_overall['p50_ms']:.3f} ms, tail(P95)={rtt_overall['p95_ms']:.3f} ms, max={rtt_overall['max_ms']:.3f} ms\n"
                if not ja
                else f"- 全体: 件数={int(rtt_overall['count'])}, 平均={rtt_overall['avg_ms']:.3f} ms, 中央値(P50)={rtt_overall['p50_ms']:.3f} ms, テール(P95)={rtt_overall['p95_ms']:.3f} ms, 最大={rtt_overall['max_ms']:.3f} ms\n"
            )
            for d in sorted(rtt_by_direction.keys()):
                s = rtt_by_direction[d]
                f.write(
                    (
                        f"- {d}: count={int(s['count'])}, mean={s['avg_ms']:.3f} ms, median(P50)={s['p50_ms']:.3f} ms, tail(P95)={s['p95_ms']:.3f} ms, max={s['max_ms']:.3f} ms\n"
                        if not ja
                        else f"- {d}: 件数={int(s['count'])}, 平均={s['avg_ms']:.3f} ms, 中央値(P50)={s['p50_ms']:.3f} ms, テール(P95)={s['p95_ms']:.3f} ms, 最大={s['max_ms']:.3f} ms\n"
                    )
                )
        else:
            f.write(
                "- No RTT samples (`tcp.analysis.ack_rtt`) found in capture\n"
                if not ja
                else "- RTTサンプル（`tcp.analysis.ack_rtt`）は取得されませんでした\n"
            )
        f.write("\n")

        f.write(
            f"## {'Multichannel Observability' if not ja else 'マルチチャネル観測'}\n\n"
        )
        if multichannel_sessions:
            f.write(
                (
                    f"- Sessions on multiple TCP streams: `{len(multichannel_sessions)}`\n"
                    if not ja
                    else f"- 複数TCPストリームに跨るセッション数: `{len(multichannel_sessions)}`\n"
                )
            )
            for s in multichannel_sessions[:10]:
                if cfg.client_ip and cfg.server_ip:
                    f.write(
                        (
                            f"- session `{s['smb_session_id']}`: streams={s['stream_count']} [{s['streams']}], c2s_streams={s['c2s_streams']} [{s['c2s_streams_list']}], s2c_streams={s['s2c_streams']} [{s['s2c_streams_list']}], smb_packets={s['smb_packets']}, p95={s['smb_p95_ms']:.3f} ms\n"
                            if not ja
                            else f"- session `{s['smb_session_id']}`: ストリーム数={s['stream_count']} [{s['streams']}], c2sストリーム={s['c2s_streams']} [{s['c2s_streams_list']}], s2cストリーム={s['s2c_streams']} [{s['s2c_streams_list']}], SMBパケット={s['smb_packets']}, P95={s['smb_p95_ms']:.3f} ms\n"
                        )
                    )
                else:
                    f.write(
                        (
                            f"- session `{s['smb_session_id']}`: streams={s['stream_count']} [{s['streams']}], smb_packets={s['smb_packets']}, p95={s['smb_p95_ms']:.3f} ms\n"
                            if not ja
                            else f"- session `{s['smb_session_id']}`: ストリーム数={s['stream_count']} [{s['streams']}], SMBパケット={s['smb_packets']}, P95={s['smb_p95_ms']:.3f} ms\n"
                        )
                    )
        else:
            f.write(
                "- No SMB sessions spanning multiple TCP streams were detected\n"
                if not ja
                else "- 複数TCPストリームに跨るSMBセッションは検出されませんでした\n"
            )
        f.write("\n")

        f.write(f"## {'Per-Stream Diagnostics (Top)' if not ja else 'TCPストリーム別診断（上位）'}\n\n")
        if stream_diagnosis_rows:
            for s in stream_diagnosis_rows[:10]:
                if not ja:
                    f.write(
                        f"- stream `{s['tcp_stream']}`: score={s['diagnostic_score']}, primary={s['primary_issue']}, "
                        f"triggers={s['triggered_actions'] or 'none'}, smb_p95={s['smb_p95_ms']} ms, "
                        f"rtt_p95={s['rtt_p95_ms']} ms, retrans={s['retransmissions']}, dup_ack={s['dup_acks']}, "
                        f"zero_window={s['zero_window']}, window_full={s['window_full']}, smb_packets={s['smb_packets']}\n"
                    )
                else:
                    f.write(
                        f"- stream `{s['tcp_stream']}`: スコア={s['diagnostic_score']}, 主要論点={s['primary_issue']}, "
                        f"トリガー={s['triggered_actions'] or 'なし'}, smb_p95={s['smb_p95_ms']} ms, "
                        f"rtt_p95={s['rtt_p95_ms']} ms, retrans={s['retransmissions']}, dup_ack={s['dup_acks']}, "
                        f"zero_window={s['zero_window']}, window_full={s['window_full']}, smb_packets={s['smb_packets']}\n"
                    )
        else:
            f.write(
                "- No TCP stream-level SMB diagnostics available\n"
                if not ja
                else "- TCPストリーム単位のSMB診断データはありません\n"
            )
        f.write("\n")

        f.write(
            f"## {'Connection Setup Analysis' if not ja else '接続確立フェーズ分析'}\n\n"
        )
        f.write(
            (
                f"- Session setup responses: `{int(setup_summary['session_setup_rsp_count'])}`\n"
                if not ja
                else f"- Session Setup 応答数: `{int(setup_summary['session_setup_rsp_count'])}`\n"
            )
        )
        f.write(
            (
                f"- Session setup avg/p95: `{setup_summary['session_setup_avg_ms']:.3f}` / `{setup_summary['session_setup_p95_ms']:.3f}` ms\n"
                if not ja
                else f"- Session Setup 平均/P95: `{setup_summary['session_setup_avg_ms']:.3f}` / `{setup_summary['session_setup_p95_ms']:.3f}` ms\n"
            )
        )
        f.write(
            (
                f"- Setup window avg/p95 (negotiate req -> first tree/session setup rsp): `{setup_summary['setup_window_avg_ms']:.3f}` / `{setup_summary['setup_window_p95_ms']:.3f}` ms\n"
                if not ja
                else f"- 確立ウィンドウ平均/P95（negotiate req -> 最初の tree/session setup rsp）: `{setup_summary['setup_window_avg_ms']:.3f}` / `{setup_summary['setup_window_p95_ms']:.3f}` ms\n"
            )
        )
        setup_source = "session-id correlation"
        if setup_summary.get("setup_window_source") == "stream_fallback":
            setup_source = "tcp.stream fallback"
        if ja:
            setup_source = (
                "セッションID相関"
                if setup_summary.get("setup_window_source") != "stream_fallback"
                else "tcp.streamフォールバック"
            )
        f.write(
            (
                f"- Setup window samples/source: `{int(setup_summary.get('setup_window_count', 0))}` / `{setup_source}`\n"
                if not ja
                else f"- 確立ウィンドウサンプル/算出元: `{int(setup_summary.get('setup_window_count', 0))}` / `{setup_source}`\n"
            )
        )
        f.write(
            (
                f"- Session setup success/non-success: `{int(setup_summary['session_setup_success'])}` / `{int(setup_summary['session_setup_non_success'])}`\n"
                if not ja
                else f"- Session Setup 成功/非成功: `{int(setup_summary['session_setup_success'])}` / `{int(setup_summary['session_setup_non_success'])}`\n"
            )
        )
        f.write(
            (
                f"- Auth-failure-like statuses in setup: `{int(setup_summary['auth_failure_like'])}`\n\n"
                if not ja
                else f"- 認証失敗系ステータス（setup内）: `{int(setup_summary['auth_failure_like'])}`\n\n"
            )
        )

        f.write(f"## {'SMB Properties' if not ja else 'SMBプロパティ'}\n\n")
        f.write(f"- {'SMB1 packets' if not ja else 'SMB1パケット数'}: `{smb_props['smb1_packets']}`\n")
        f.write(f"- {'SMB2/3 packets' if not ja else 'SMB2/3パケット数'}: `{smb_props['smb2_packets']}`\n")
        f.write(f"- {'Dialects seen' if not ja else '検出ダイアレクト'}: `{smb_props['dialects_text']}`\n")
        f.write(f"- {'Signing enabled (negotiated)' if not ja else '署名有効(ネゴシエート)'}: `{yes_no(bool(smb_props['sign_enabled']), cfg.lang)}`\n")
        f.write(f"- {'Signing required (negotiated)' if not ja else '署名必須(ネゴシエート)'}: `{yes_no(bool(smb_props['sign_required']), cfg.lang)}`\n")
        f.write(f"- {'Session encryption flag observed' if not ja else 'セッション暗号化フラグ検出'}: `{yes_no(bool(smb_props['session_encrypt']), cfg.lang)}`\n")
        f.write(f"- {'Encryption capability advertised' if not ja else '暗号化機能の広告'}: `{yes_no(bool(smb_props['cap_encryption']), cfg.lang)}`\n")
        f.write(f"- {'Max read size seen' if not ja else '最大Readサイズ'}: `{smb_props['max_read']}` bytes\n")
        f.write(f"- {'Max write size seen' if not ja else '最大Writeサイズ'}: `{smb_props['max_write']}` bytes\n")
        f.write(f"- {'Max transaction size seen' if not ja else '最大Transactionサイズ'}: `{smb_props['max_trans']}` bytes\n\n")

        f.write(f"## {'Latency (smb2.time)' if not ja else '遅延 (smb2.time)'}\n\n")
        if not ja:
            f.write("- Definition: `smb2.time` = SMB request-to-response latency\n")
            f.write("- Unit: `ms` (milliseconds)\n\n")
        else:
            f.write("- 定義: `smb2.time` = SMBのリクエストからレスポンスまでの遅延\n")
            f.write("- 単位: `ms`（ミリ秒）\n\n")
        f.write(f"- {'Count' if not ja else '件数'}: `{int(smb_latency['count'])}`\n")
        f.write(f"- {'Avg (mean)' if not ja else '平均'}: `{smb_latency['avg_ms']:.3f} ms`\n")
        f.write(f"- {'Median (P50)' if not ja else '中央値 (P50)'}: `{smb_latency['p50_ms']:.3f} ms`\n")
        f.write(f"- {'Tail latency (P95)' if not ja else 'テール遅延 (P95)'}: `{smb_latency['p95_ms']:.3f} ms`\n")
        f.write(f"- {'Max' if not ja else '最大'}: `{smb_latency['max_ms']:.3f} ms`\n\n")

        f.write(f"## {'Key Findings' if not ja else '主要所見'}\n\n")
        for item in findings:
            f.write(f"- {item}\n")
        f.write("\n")

        f.write(f"## {'Recommended Next Actions' if not ja else '推奨される次アクション'}\n\n")
        for a in actions:
            f.write(f"{a['id']}. [{a['status']}] {a['title']}\n")
            f.write(f"{'Trigger' if not ja else 'トリガー'}: {a['trigger']}\n")
            f.write(f"{'Criteria' if not ja else '判定基準'}: {a['criteria']}\n")
            f.write(f"{'Threshold' if not ja else '閾値判定'}: {a['threshold']}\n")
            f.write(
                f"{'Threshold Source' if not ja else '閾値の根拠種別'}: {a.get('source_type', 'unknown')}\n"
            )
            f.write(
                f"{'Confidence' if not ja else '信頼度'}: {a.get('confidence', 'unknown')}\n"
            )
            f.write(f"{'Next' if not ja else '次アクション'}: {a['next']}\n")
            f.write(
                f"{'Evidence' if not ja else '根拠URL'}: {format_links(a.get('evidence', a['refs']))}\n"
            )
            f.write(f"{'Refs' if not ja else '参照'}: {format_links(a['refs'])}\n\n")

        f.write(
            f"## {'Top Slow Commands (by P95)' if not ja else '遅いコマンド上位 (P95順)'}\n\n"
        )
        if top_cmd:
            for cmd, s in top_cmd[:10]:
                cmd_name = SMB2_CMD_NAMES.get(cmd, "UNKNOWN")
                f.write(
                    (
                        f"- cmd `{cmd}` ({cmd_name}): count={int(s['count'])}, mean={s['avg_ms']:.3f} ms, median(P50)={s['p50_ms']:.3f} ms, tail(P95)={s['p95_ms']:.3f} ms, max={s['max_ms']:.3f} ms\n"
                        if not ja
                        else f"- cmd `{cmd}` ({cmd_name}): 件数={int(s['count'])}, 平均={s['avg_ms']:.3f} ms, 中央値(P50)={s['p50_ms']:.3f} ms, テール(P95)={s['p95_ms']:.3f} ms, 最大={s['max_ms']:.3f} ms\n"
                    )
                )
        else:
            f.write(
                "- Not available (likely no-key mode visibility limits or decryption unavailable)\n"
                if not ja
                else "- 利用不可（no-keyモードの可視性制約、または復号不可の可能性）\n"
            )
        f.write("\n")

        f.write(f"## {'Top NTSTATUS' if not ja else '主要NTSTATUS'}\n\n")
        if status_counts:
            total_status = sum(status_counts.values())
            success = status_counts.get("0x00000000", 0)
            error = total_status - success
            f.write(
                (
                    f"- NTSTATUS sampled responses: `{total_status}` (success `{success}`, non-success `{error}`)\n"
                    if not ja
                    else f"- NTSTATUSサンプル応答: `{total_status}` (成功 `{success}`, 非成功 `{error}`)\n"
                )
            )
            for st, cnt in status_counts.most_common(10):
                pct = (cnt / max(1, total_status)) * 100.0
                label = NTSTATUS_HINTS.get(st, "Unknown/See MS-ERREF")
                kind = ("success" if st == "0x00000000" else "non-success") if not ja else ("成功" if st == "0x00000000" else "非成功")
                f.write(
                    f"- `{st}` `{label}` ({kind}): `{cnt}` ({pct:.1f}%)\n"
                )
        else:
            f.write("- Not available\n" if not ja else "- 利用不可\n")
        f.write("\n")

        f.write(f"## {'I/O Size Latency' if not ja else 'I/Oサイズ別遅延'}\n\n")
        if io_size_stats:
            for b in [
                "0-4KiB",
                "4-16KiB",
                "16-64KiB",
                "64-256KiB",
                "256KiB-1MiB",
                "1MiB+",
                "unknown",
            ]:
                vals = io_size_stats.get(b, [])
                if not vals:
                    continue
                s = summarize_latency(vals)
                f.write(
                    (
                        f"- `{b}`: count={int(s['count'])}, mean={s['avg_ms']:.3f} ms, median(P50)={s['p50_ms']:.3f} ms, tail(P95)={s['p95_ms']:.3f} ms, max={s['max_ms']:.3f} ms\n"
                        if not ja
                        else f"- `{b}`: 件数={int(s['count'])}, 平均={s['avg_ms']:.3f} ms, 中央値(P50)={s['p50_ms']:.3f} ms, テール(P95)={s['p95_ms']:.3f} ms, 最大={s['max_ms']:.3f} ms\n"
                    )
                )
        else:
            f.write("- Not available\n" if not ja else "- 利用不可\n")


def main() -> int:
    cfg = parse_args()
    check_prereq(cfg)
    os.makedirs(cfg.outdir, exist_ok=True)

    mode, extra_opts, keys = detect_mode(cfg)
    filt = base_filter(cfg)

    fields = [
        "frame.time_epoch",
        "frame.len",
        "tcp.stream",
        "ip.src",
        "ip.dst",
        "tcp.analysis.retransmission",
        "tcp.analysis.duplicate_ack",
        "tcp.analysis.zero_window",
        "tcp.analysis.window_full",
        "tcp.analysis.ack_rtt",
        "smb2.flags.response",
        "smb2.cmd",
        "smb.cmd",
        "smb2.msg_id",
        "smb2.sesid",
        "smb2.time",
        "smb2.nt_status",
        "smb2.credit.charge",
        "smb2.credits.requested",
        "smb2.credits.granted",
        "smb2.filename",
        "smb2.header.transform.flags.encrypted",
        "smb2.read_length",
        "smb2.write_length",
        "smb2.write.count",
        "smb2.dialect",
        "smb2.sec_mode.sign_enabled",
        "smb2.sec_mode.sign_required",
        "smb2.ses_flags.encrypt",
        "smb2.capabilities.encryption",
        "smb2.max_read_size",
        "smb2.max_write_size",
        "smb2.max_trans_size",
    ]

    rows = tshark_fields(cfg, fields, filt, extra_opts=extra_opts)
    if not rows:
        print("No matching packets found for filter:", filt, file=sys.stderr)
        return 2

    timeline_rows = timeline_from_rows(rows, cfg.interval, cfg.client_ip, cfg.server_ip)
    write_csv(
        os.path.join(cfg.outdir, "timeline.csv"),
        timeline_rows,
        [
            "bucket_start",
            "frames",
            "bytes",
            "retransmissions",
            "dup_acks",
            "zero_window",
            "window_full",
            "smb_req",
            "smb_rsp",
            "avg_smb_time_ms",
        ],
    )

    op_rows = []
    status_counts = Counter()
    cmd_latency: dict[str, list[float]] = defaultdict(list)
    smb_lat_all = []
    credit_pressure_count = 0
    retrans = dup_ack = zero_window = window_full = 0
    pending = set()
    outstanding = 0
    outstanding_peak = 0
    encrypted_payload_frames = 0
    io_size_latency: dict[str, list[float]] = defaultdict(list)
    req_io_size: dict[tuple[str, str], int] = {}
    smb1_packets = 0
    smb2_packets = 0
    dialects_seen: set[str] = set()
    sign_enabled = False
    sign_required = False
    session_encrypt = False
    cap_encryption = False
    max_read_seen = 0
    max_write_seen = 0
    max_trans_seen = 0
    rtt_all_ms: list[float] = []
    rtt_dir_ms: dict[str, list[float]] = defaultdict(list)
    rtt_stream_ms: dict[str, list[float]] = defaultdict(list)
    session_streams: dict[str, set[str]] = defaultdict(set)
    session_c2s_streams: dict[str, set[str]] = defaultdict(set)
    session_s2c_streams: dict[str, set[str]] = defaultdict(set)
    session_smb_times_ms: dict[str, list[float]] = defaultdict(list)
    session_packets: Counter = Counter()
    session_req: Counter = Counter()
    session_rsp: Counter = Counter()
    session_c2s_packets: Counter = Counter()
    session_s2c_packets: Counter = Counter()
    session_status: dict[str, Counter] = defaultdict(Counter)
    stream_smb_times_ms: dict[tuple[str, str], list[float]] = defaultdict(list)
    stream_packets: Counter = Counter()
    stream_c2s_packets: Counter = Counter()
    stream_s2c_packets: Counter = Counter()
    stream_retrans: Counter = Counter()
    stream_dup_ack: Counter = Counter()
    stream_zero_window: Counter = Counter()
    stream_window_full: Counter = Counter()
    stream_frame_count: Counter = Counter()
    stream_smb_packets: Counter = Counter()
    stream_smb_req: Counter = Counter()
    stream_smb_rsp: Counter = Counter()
    stream_status: dict[str, Counter] = defaultdict(Counter)
    stream_credit_pressure: Counter = Counter()
    stream_smb_lat_ms: dict[str, list[float]] = defaultdict(list)

    rows_sorted = sorted(rows, key=lambda x: to_float(x.get("frame.time_epoch", "0")))
    setup_rows, setup_summary = analyze_connection_setup(rows_sorted)

    for r in rows_sorted:
        stream_key = r.get("tcp.stream", "")
        if stream_key:
            stream_frame_count[stream_key] += 1
        if r.get("tcp.analysis.retransmission"):
            retrans += 1
            if stream_key:
                stream_retrans[stream_key] += 1
        if r.get("tcp.analysis.duplicate_ack"):
            dup_ack += 1
            if stream_key:
                stream_dup_ack[stream_key] += 1
        if r.get("tcp.analysis.zero_window"):
            zero_window += 1
            if stream_key:
                stream_zero_window[stream_key] += 1
        if r.get("tcp.analysis.window_full"):
            window_full += 1
            if stream_key:
                stream_window_full[stream_key] += 1
        ack_rtt_s = to_float(r.get("tcp.analysis.ack_rtt", "0"))
        if ack_rtt_s > 0:
            rtt_ms = ack_rtt_s * 1000.0
            rtt_all_ms.append(rtt_ms)
            src = r.get("ip.src", "")
            dst = r.get("ip.dst", "")
            if cfg.client_ip and cfg.server_ip:
                if src == cfg.client_ip and dst == cfg.server_ip:
                    dir_key = "client_to_server_ack"
                elif src == cfg.server_ip and dst == cfg.client_ip:
                    dir_key = "server_to_client_ack"
                else:
                    dir_key = "other"
            else:
                dir_key = f"{src}->{dst}" if src and dst else "unknown"
            rtt_dir_ms[dir_key].append(rtt_ms)
            if stream_key:
                rtt_stream_ms[stream_key].append(rtt_ms)
        if r.get("smb.cmd", ""):
            smb1_packets += 1
        if r.get("smb2.cmd", "") or r.get("smb2.dialect", ""):
            smb2_packets += 1

        for d in str(r.get("smb2.dialect", "")).split(","):
            d = d.strip()
            if d:
                dialects_seen.add(d)
        sign_enabled = sign_enabled or to_bool(r.get("smb2.sec_mode.sign_enabled", ""))
        sign_required = sign_required or to_bool(r.get("smb2.sec_mode.sign_required", ""))
        session_encrypt = session_encrypt or to_bool(r.get("smb2.ses_flags.encrypt", ""))
        cap_encryption = cap_encryption or to_bool(r.get("smb2.capabilities.encryption", ""))
        max_read_seen = max(max_read_seen, to_int(r.get("smb2.max_read_size", "0")))
        max_write_seen = max(max_write_seen, to_int(r.get("smb2.max_write_size", "0")))
        max_trans_seen = max(max_trans_seen, to_int(r.get("smb2.max_trans_size", "0")))

        nt = r.get("smb2.nt_status", "")
        if nt:
            status_counts[nt] += 1
            if stream_key and nt != "0x00000000":
                stream_status[stream_key][nt] += 1

        req = to_int(r.get("smb2.credits.requested", "0"))
        grant = to_int(r.get("smb2.credits.granted", "0"))
        if req > 0 and grant > 0 and req > grant:
            credit_pressure_count += 1
            if stream_key:
                stream_credit_pressure[stream_key] += 1
        if r.get("smb2.header.transform.flags.encrypted"):
            encrypted_payload_frames += 1

        msg_id = r.get("smb2.msg_id", "")
        stream = stream_key
        sesid = r.get("smb2.sesid", "")
        is_response = to_bool(r.get("smb2.flags.response", "0"))
        src = r.get("ip.src", "")
        dst = r.get("ip.dst", "")
        if sesid:
            session_packets[sesid] += 1
            if stream:
                session_streams[sesid].add(stream)
            if is_response:
                session_rsp[sesid] += 1
            else:
                session_req[sesid] += 1
            nt = r.get("smb2.nt_status", "")
            if nt and nt != "0x00000000":
                session_status[sesid][nt] += 1
            if cfg.client_ip and cfg.server_ip:
                if src == cfg.client_ip and dst == cfg.server_ip:
                    session_c2s_packets[sesid] += 1
                    if stream:
                        session_c2s_streams[sesid].add(stream)
                elif src == cfg.server_ip and dst == cfg.client_ip:
                    session_s2c_packets[sesid] += 1
                    if stream:
                        session_s2c_streams[sesid].add(stream)
        if sesid and stream:
            stream_packets[(sesid, stream)] += 1
            if cfg.client_ip and cfg.server_ip:
                if src == cfg.client_ip and dst == cfg.server_ip:
                    stream_c2s_packets[(sesid, stream)] += 1
                elif src == cfg.server_ip and dst == cfg.client_ip:
                    stream_s2c_packets[(sesid, stream)] += 1

        if msg_id and stream:
            key = (stream, msg_id)
            cmd = normalize_smb2_cmd(r.get("smb2.cmd", ""))
            if not is_response and cmd in {"8", "9"}:
                req_io_size[key] = to_int(
                    r.get("smb2.read_length", "")
                    if cmd == "8"
                    else (r.get("smb2.write_length", "") or r.get("smb2.write.count", ""))
                )
            if not is_response:
                if key not in pending:
                    pending.add(key)
                    outstanding += 1
                    outstanding_peak = max(outstanding_peak, outstanding)
            else:
                if key in pending:
                    pending.remove(key)
                    outstanding = max(0, outstanding - 1)

        t_s = to_float(r.get("smb2.time", "0"))
        if t_s > 0:
            ms = t_s * 1000.0
            smb_lat_all.append(ms)
            cmd = normalize_smb2_cmd(r.get("smb2.cmd", ""))
            if sesid:
                session_smb_times_ms[sesid].append(ms)
                if stream:
                    stream_smb_times_ms[(sesid, stream)].append(ms)
            if cmd:
                if stream:
                    stream_smb_packets[stream] += 1
                    if is_response:
                        stream_smb_rsp[stream] += 1
                    else:
                        stream_smb_req[stream] += 1
                    stream_smb_lat_ms[stream].append(ms)
                io_size = 0
                if cmd in {"8", "9"} and stream and msg_id:
                    io_size = req_io_size.get((stream, msg_id), 0)
                cmd_latency[cmd].append(ms)
                op_rows.append(
                    {
                        "time_epoch": r.get("frame.time_epoch", ""),
                        "cmd": cmd,
                        "cmd_name": SMB2_CMD_NAMES.get(cmd, "UNKNOWN"),
                        "msg_id": msg_id,
                        "latency_ms": f"{ms:.3f}",
                        "io_size_bytes": str(io_size) if io_size > 0 else "",
                        "src": r.get("ip.src", ""),
                        "dst": r.get("ip.dst", ""),
                        "filename": r.get("smb2.filename", ""),
                    }
                )
                if cmd in {"8", "9"}:
                    io_size_latency[size_bucket(io_size)].append(ms)

    op_rows.sort(key=lambda x: float(str(x["latency_ms"])), reverse=True)
    write_csv(
        os.path.join(cfg.outdir, "top_slow_ops.csv"),
        op_rows[: cfg.max_slow_ops],
        [
            "time_epoch",
            "cmd",
            "cmd_name",
            "msg_id",
            "latency_ms",
            "io_size_bytes",
            "src",
            "dst",
            "filename",
        ],
    )

    io_rows = []
    for bucket in [
        "0-4KiB",
        "4-16KiB",
        "16-64KiB",
        "64-256KiB",
        "256KiB-1MiB",
        "1MiB+",
        "unknown",
    ]:
        vals = io_size_latency.get(bucket, [])
        if not vals:
            continue
        s = summarize_latency(vals)
        io_rows.append(
            {
                "size_bucket": bucket,
                "count": int(s["count"]),
                "avg_ms": f"{s['avg_ms']:.3f}",
                "p50_ms": f"{s['p50_ms']:.3f}",
                "p95_ms": f"{s['p95_ms']:.3f}",
                "max_ms": f"{s['max_ms']:.3f}",
            }
        )
    write_csv(
        os.path.join(cfg.outdir, "io_size_latency.csv"),
        io_rows,
        ["size_bucket", "count", "avg_ms", "p50_ms", "p95_ms", "max_ms"],
    )
    write_csv(
        os.path.join(cfg.outdir, "connection_setup_summary.csv"),
        setup_rows,
        [
            "smb_session_id",
            "setup_window_ms",
            "negotiate_rsp_count",
            "negotiate_p95_ms",
            "session_setup_rsp_count",
            "session_setup_p95_ms",
            "session_setup_success",
            "session_setup_non_success",
            "session_setup_more_processing",
            "auth_failure_like",
            "tree_connect_rsp_count",
            "tree_connect_p95_ms",
        ],
    )

    st_rows = [{"nt_status": k, "count": v} for k, v in status_counts.most_common()]
    write_csv(os.path.join(cfg.outdir, "ntstatus_counts.csv"), st_rows, ["nt_status", "count"])

    smb_latency = summarize_latency(smb_lat_all)
    rtt_overall = summarize_latency(rtt_all_ms)
    rtt_by_direction = {k: summarize_latency(v) for k, v in rtt_dir_ms.items()}
    dialect_labels = []
    for d in sorted(dialects_seen):
        dialect_labels.append(f"{d} ({SMB_DIALECT_NAMES.get(d, 'Unknown')})")
    smb_props = {
        "smb1_packets": smb1_packets,
        "smb2_packets": smb2_packets,
        "dialects_text": ", ".join(dialect_labels) if dialect_labels else "N/A",
        "sign_enabled": sign_enabled,
        "sign_required": sign_required,
        "session_encrypt": session_encrypt,
        "cap_encryption": cap_encryption,
        "max_read": max_read_seen,
        "max_write": max_write_seen,
        "max_trans": max_trans_seen,
    }

    session_rows = []
    for sesid in sorted(session_packets.keys()):
        s_stats = summarize_latency(session_smb_times_ms.get(sesid, []))
        streams = sorted(session_streams.get(sesid, set()), key=lambda x: int(x) if x.isdigit() else x)
        st_counter = session_status.get(sesid, Counter())
        top_st = st_counter.most_common(1)[0][0] if st_counter else ""
        session_rows.append(
            {
                "smb_session_id": sesid,
                "stream_count": len(streams),
                "streams": ";".join(streams),
                "smb_packets": int(session_packets[sesid]),
                "smb_req": int(session_req[sesid]),
                "smb_rsp": int(session_rsp[sesid]),
                "c2s_packets": int(session_c2s_packets.get(sesid, 0)),
                "s2c_packets": int(session_s2c_packets.get(sesid, 0)),
                "c2s_stream_count": len(session_c2s_streams.get(sesid, set())),
                "s2c_stream_count": len(session_s2c_streams.get(sesid, set())),
                "c2s_streams": ";".join(
                    sorted(
                        session_c2s_streams.get(sesid, set()),
                        key=lambda x: int(x) if x.isdigit() else x,
                    )
                ),
                "s2c_streams": ";".join(
                    sorted(
                        session_s2c_streams.get(sesid, set()),
                        key=lambda x: int(x) if x.isdigit() else x,
                    )
                ),
                "smb_time_count": int(s_stats["count"]),
                "smb_avg_ms": f"{s_stats['avg_ms']:.3f}",
                "smb_p50_ms": f"{s_stats['p50_ms']:.3f}",
                "smb_p95_ms": f"{s_stats['p95_ms']:.3f}",
                "smb_max_ms": f"{s_stats['max_ms']:.3f}",
                "non_success_status_count": int(sum(st_counter.values())),
                "top_non_success_status": top_st,
            }
        )
    write_csv(
        os.path.join(cfg.outdir, "smb_session_summary.csv"),
        session_rows,
        [
            "smb_session_id",
            "stream_count",
            "streams",
            "smb_packets",
            "smb_req",
            "smb_rsp",
            "c2s_packets",
            "s2c_packets",
            "c2s_stream_count",
            "s2c_stream_count",
            "c2s_streams",
            "s2c_streams",
            "smb_time_count",
            "smb_avg_ms",
            "smb_p50_ms",
            "smb_p95_ms",
            "smb_max_ms",
            "non_success_status_count",
            "top_non_success_status",
        ],
    )

    channel_rows = []
    for sesid, stream in sorted(stream_packets.keys(), key=lambda x: (x[0], int(x[1]) if x[1].isdigit() else x[1])):
        c_stats = summarize_latency(stream_smb_times_ms.get((sesid, stream), []))
        channel_rows.append(
            {
                "smb_session_id": sesid,
                "tcp_stream": stream,
                "smb_packets": int(stream_packets[(sesid, stream)]),
                "smb_time_count": int(c_stats["count"]),
                "smb_avg_ms": f"{c_stats['avg_ms']:.3f}",
                "smb_p50_ms": f"{c_stats['p50_ms']:.3f}",
                "smb_p95_ms": f"{c_stats['p95_ms']:.3f}",
                "smb_max_ms": f"{c_stats['max_ms']:.3f}",
                "c2s_packets": int(stream_c2s_packets.get((sesid, stream), 0)),
                "s2c_packets": int(stream_s2c_packets.get((sesid, stream), 0)),
                "retransmissions": int(stream_retrans.get(stream, 0)),
                "dup_acks": int(stream_dup_ack.get(stream, 0)),
                "zero_window": int(stream_zero_window.get(stream, 0)),
                "window_full": int(stream_window_full.get(stream, 0)),
            }
        )
    write_csv(
        os.path.join(cfg.outdir, "smb_channel_summary.csv"),
        channel_rows,
        [
            "smb_session_id",
            "tcp_stream",
            "smb_packets",
            "smb_time_count",
            "smb_avg_ms",
            "smb_p50_ms",
            "smb_p95_ms",
            "smb_max_ms",
            "c2s_packets",
            "s2c_packets",
            "retransmissions",
            "dup_acks",
            "zero_window",
            "window_full",
        ],
    )

    multichannel_sessions = []
    for r in session_rows:
        if int(r["stream_count"]) > 1:
            multichannel_sessions.append(
                {
                    "smb_session_id": r["smb_session_id"],
                    "stream_count": int(r["stream_count"]),
                    "streams": r["streams"],
                    "c2s_streams": int(r["c2s_stream_count"]),
                    "s2c_streams": int(r["s2c_stream_count"]),
                    "c2s_streams_list": r["c2s_streams"],
                    "s2c_streams_list": r["s2c_streams"],
                    "smb_packets": int(r["smb_packets"]),
                    "smb_p95_ms": float(r["smb_p95_ms"]),
                }
            )
    multichannel_sessions.sort(key=lambda x: (x["stream_count"], x["smb_p95_ms"]), reverse=True)

    stream_diag_rows = []
    all_stream_ids = set(stream_frame_count.keys())
    all_stream_ids.update(stream_smb_packets.keys())
    all_stream_ids.update(rtt_stream_ms.keys())
    all_stream_ids.update(stream_retrans.keys())
    all_stream_ids.update(stream_dup_ack.keys())
    all_stream_ids.update(stream_zero_window.keys())
    all_stream_ids.update(stream_window_full.keys())
    all_stream_ids.update(stream_status.keys())
    all_stream_ids.update(stream_credit_pressure.keys())
    for sid in sorted(all_stream_ids, key=lambda x: int(x) if x.isdigit() else x):
        frame_cnt = int(stream_frame_count.get(sid, 0))
        smb_stats = summarize_latency(stream_smb_lat_ms.get(sid, []))
        rtt_stats = summarize_latency(rtt_stream_ms.get(sid, []))
        retrans_c = int(stream_retrans.get(sid, 0))
        dup_c = int(stream_dup_ack.get(sid, 0))
        zero_c = int(stream_zero_window.get(sid, 0))
        winfull_c = int(stream_window_full.get(sid, 0))
        credit_c = int(stream_credit_pressure.get(sid, 0))
        st_counter = stream_status.get(sid, Counter())
        st_total = int(sum(st_counter.values()))
        auth_acl_hits = int(
            st_counter.get("0xc000006d", 0)
            + st_counter.get("0xc0000022", 0)
            + st_counter.get("0xc0000034", 0)
        )
        auth_acl_pct = (auth_acl_hits / max(1, st_total)) * 100.0
        retrans_pct = (retrans_c / max(1, frame_cnt)) * 100.0
        dup_pct = (dup_c / max(1, frame_cnt)) * 100.0
        zero_pct = (zero_c / max(1, frame_cnt)) * 100.0
        winfull_pct = (winfull_c / max(1, frame_cnt)) * 100.0

        t1 = retrans_c >= 3 or retrans_pct >= 0.10 or dup_c >= 10 or dup_pct >= 0.20
        t2 = zero_c >= 3 or zero_pct >= 0.05 or winfull_c >= 10 or winfull_pct >= 0.20
        t3 = (
            smb_stats["p95_ms"] >= 100.0
            and retrans_c < 3
            and (rtt_stats["count"] == 0 or rtt_stats["p95_ms"] <= 20.0)
        )
        t4 = auth_acl_hits >= 3 or auth_acl_pct >= 5.0
        t5 = credit_c >= 5
        triggered = []
        if t1:
            triggered.append("1")
        if t2:
            triggered.append("2")
        if t3:
            triggered.append("3")
        if t4:
            triggered.append("4")
        if t5:
            triggered.append("5")
        primary = "none"
        if t1:
            primary = "network_quality"
        elif t2:
            primary = "receiver_backpressure"
        elif t3:
            primary = "server_storage_delay"
        elif t4:
            primary = "auth_acl_errors"
        elif t5:
            primary = "credit_bottleneck"
        score = len(triggered) * 100
        score += retrans_c * 5 + dup_c * 2 + zero_c * 3 + winfull_c * 2
        score += int(smb_stats["p95_ms"] / 10.0) + int(rtt_stats["p95_ms"] / 10.0)
        stream_diag_rows.append(
            {
                "tcp_stream": sid,
                "diagnostic_score": score,
                "primary_issue": primary,
                "triggered_actions": ",".join(triggered),
                "stream_frames": frame_cnt,
                "smb_packets": int(stream_smb_packets.get(sid, 0)),
                "smb_req": int(stream_smb_req.get(sid, 0)),
                "smb_rsp": int(stream_smb_rsp.get(sid, 0)),
                "smb_time_count": int(smb_stats["count"]),
                "smb_avg_ms": f"{smb_stats['avg_ms']:.3f}",
                "smb_p50_ms": f"{smb_stats['p50_ms']:.3f}",
                "smb_p95_ms": f"{smb_stats['p95_ms']:.3f}",
                "smb_max_ms": f"{smb_stats['max_ms']:.3f}",
                "rtt_count": int(rtt_stats["count"]),
                "rtt_avg_ms": f"{rtt_stats['avg_ms']:.3f}",
                "rtt_p50_ms": f"{rtt_stats['p50_ms']:.3f}",
                "rtt_p95_ms": f"{rtt_stats['p95_ms']:.3f}",
                "rtt_max_ms": f"{rtt_stats['max_ms']:.3f}",
                "retransmissions": retrans_c,
                "dup_acks": dup_c,
                "zero_window": zero_c,
                "window_full": winfull_c,
                "credit_pressure_events": credit_c,
                "auth_acl_related": auth_acl_hits,
                "auth_acl_related_pct": f"{auth_acl_pct:.2f}",
            }
        )
    stream_diag_rows.sort(
        key=lambda r: (
            int(r["diagnostic_score"]),
            int(r["smb_packets"]),
            float(str(r["smb_p95_ms"])),
        ),
        reverse=True,
    )
    write_csv(
        os.path.join(cfg.outdir, "stream_diagnosis.csv"),
        stream_diag_rows,
        [
            "tcp_stream",
            "diagnostic_score",
            "primary_issue",
            "triggered_actions",
            "stream_frames",
            "smb_packets",
            "smb_req",
            "smb_rsp",
            "smb_time_count",
            "smb_avg_ms",
            "smb_p50_ms",
            "smb_p95_ms",
            "smb_max_ms",
            "rtt_count",
            "rtt_avg_ms",
            "rtt_p50_ms",
            "rtt_p95_ms",
            "rtt_max_ms",
            "retransmissions",
            "dup_acks",
            "zero_window",
            "window_full",
            "credit_pressure_events",
            "auth_acl_related",
            "auth_acl_related_pct",
        ],
    )

    write_markdown_summary(
        cfg=cfg,
        mode=mode,
        total_frames=len(rows),
        total_bytes=sum(to_int(r.get("frame.len", "0")) for r in rows),
        smb_latency=smb_latency,
        status_counts=status_counts,
        cmd_latency=cmd_latency,
        credit_pressure_count=credit_pressure_count,
        outstanding_peak=outstanding_peak,
        encrypted_payload_frames=encrypted_payload_frames,
        retrans_count=retrans,
        dup_ack_count=dup_ack,
        zero_window_count=zero_window,
        window_full_count=window_full,
        io_size_stats=io_size_latency,
        smb_props=smb_props,
        rtt_overall=rtt_overall,
        rtt_by_direction=rtt_by_direction,
        multichannel_sessions=multichannel_sessions,
        setup_summary=setup_summary,
        stream_diagnosis_rows=stream_diag_rows,
        out_path=os.path.join(cfg.outdir, "summary.md"),
    )

    rtt_summary_rows = [
        {
            "scope": "overall",
            "direction": "all",
            "count": int(rtt_overall["count"]),
            "avg_ms": f"{rtt_overall['avg_ms']:.3f}",
            "p50_ms": f"{rtt_overall['p50_ms']:.3f}",
            "p95_ms": f"{rtt_overall['p95_ms']:.3f}",
            "max_ms": f"{rtt_overall['max_ms']:.3f}",
        }
    ]
    for d in sorted(rtt_by_direction.keys()):
        s = rtt_by_direction[d]
        rtt_summary_rows.append(
            {
                "scope": "direction",
                "direction": d,
                "count": int(s["count"]),
                "avg_ms": f"{s['avg_ms']:.3f}",
                "p50_ms": f"{s['p50_ms']:.3f}",
                "p95_ms": f"{s['p95_ms']:.3f}",
                "max_ms": f"{s['max_ms']:.3f}",
            }
        )
    write_csv(
        os.path.join(cfg.outdir, "rtt_summary.csv"),
        rtt_summary_rows,
        ["scope", "direction", "count", "avg_ms", "p50_ms", "p95_ms", "max_ms"],
    )

    rtt_by_stream_rows = []
    for stream_id in sorted(rtt_stream_ms.keys(), key=lambda x: int(x) if x.isdigit() else x):
        s = summarize_latency(rtt_stream_ms[stream_id])
        rtt_by_stream_rows.append(
            {
                "tcp_stream": stream_id,
                "count": int(s["count"]),
                "avg_ms": f"{s['avg_ms']:.3f}",
                "p50_ms": f"{s['p50_ms']:.3f}",
                "p95_ms": f"{s['p95_ms']:.3f}",
                "max_ms": f"{s['max_ms']:.3f}",
            }
        )
    write_csv(
        os.path.join(cfg.outdir, "rtt_by_stream.csv"),
        rtt_by_stream_rows,
        ["tcp_stream", "count", "avg_ms", "p50_ms", "p95_ms", "max_ms"],
    )

    io_stat_text = ""
    try:
        io_stat_text = tshark_io_stat(cfg, filt)
    except Exception as e:
        io_stat_text = f"io,stat collection failed: {e}\n"
    with open(os.path.join(cfg.outdir, "tshark_iostat.txt"), "w", encoding="utf-8") as f:
        f.write(io_stat_text)

    smb2_srt_text = ""
    try:
        smb2_srt_text = tshark_smb2_srt(cfg, filt, extra_opts=extra_opts)
    except Exception as e:
        smb2_srt_text = f"smb2,srt collection failed: {e}\n"
    with open(os.path.join(cfg.outdir, "tshark_smb2_srt.txt"), "w", encoding="utf-8") as f:
        f.write(smb2_srt_text)

    with open(os.path.join(cfg.outdir, "run_meta.txt"), "w", encoding="utf-8") as f:
        f.write(f"mode={mode}\n")
        f.write(f"pcap={cfg.pcap}\n")
        f.write(f"filter={filt}\n")
        f.write(f"rows={len(rows)}\n")
        f.write(f"keys_loaded={len(keys)}\n")

    print(f"Done. Output directory: {cfg.outdir}")
    print(f"- {os.path.join(cfg.outdir, 'summary.md')}")
    print(f"- {os.path.join(cfg.outdir, 'timeline.csv')}")
    print(f"- {os.path.join(cfg.outdir, 'top_slow_ops.csv')}")
    print(f"- {os.path.join(cfg.outdir, 'ntstatus_counts.csv')}")
    print(f"- {os.path.join(cfg.outdir, 'io_size_latency.csv')}")
    print(f"- {os.path.join(cfg.outdir, 'rtt_summary.csv')}")
    print(f"- {os.path.join(cfg.outdir, 'rtt_by_stream.csv')}")
    print(f"- {os.path.join(cfg.outdir, 'stream_diagnosis.csv')}")
    print(f"- {os.path.join(cfg.outdir, 'connection_setup_summary.csv')}")
    print(f"- {os.path.join(cfg.outdir, 'smb_session_summary.csv')}")
    print(f"- {os.path.join(cfg.outdir, 'smb_channel_summary.csv')}")
    print(f"- {os.path.join(cfg.outdir, 'tshark_iostat.txt')}")
    print(f"- {os.path.join(cfg.outdir, 'tshark_smb2_srt.txt')}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        raise SystemExit(1)
