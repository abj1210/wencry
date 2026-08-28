#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
analyze_sched.py - 集成运行 + 日志分析 + 图表报告

功能:
  1. 生成不同大小的输入文件;
  2. 对每个大小依次运行 加密(-e)/解密(-d)/验证(-v) 三种模式(不指定 cmode,使用默认);
  3. 收集每种模式运行生成的 sched_log.csv 并解析;
  4. 输出文本对比,并生成自包含 HTML 报告(内嵌 SVG 图表):
     - 总览双轴图(吞吐柱状 + 峰值内存柱状,文件大小内按模式分组)
     - 每个大小/模式的 loaded/processed/idle 三池折线图与独立的内存占用(存活缓冲)折线图
     - 每个大小/模式的线程占用率(水平条形图)

用法:
  python analyze_sched.py [--exe 路径] [--sizes 32,200,512] [--key 密钥] [--out 输出目录] [--runs 5] [--warmup 2]

依赖: 仅标准库,无需 matplotlib/pandas。
"""
import argparse
import csv
import html
import os
import shutil
import subprocess
import sys
from collections import Counter, defaultdict


DEFAULT_KEY = "ABEiM0RVZneImaq7zN3u/w=="
MODES = [("enc", "-e"), ("dec", "-d"), ("ver", "-v")]
MODE_COLORS = {"enc": "#2b8cbe", "dec": "#f4a582", "ver": "#a6ce39"}
BUF_MIB = 16  # 单个 iobuffer 占用 0x100000 * 16B = 16MiB,用于把池内缓冲数换算成内存
BLOCK_COLOR = "#d62728"  # 甘特图中线程阻塞/空闲时间的高亮色(醒目红色)


def _int(x):
    try:
        return int(x)
    except (TypeError, ValueError):
        return None


def load_csv(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        rows = list(csv.DictReader(f))
    for r in rows:
        r["us"] = _int(r.get("us"))
        r["id"] = _int(r.get("id"))
        r["seq"] = _int(r.get("seq"))
        r["work"] = _int(r.get("work"))
        r["idle"] = _int(r.get("idle"))
        r["processed"] = _int(r.get("processed"))
        r["live"] = _int(r.get("live"))
    return rows


def _median(vals):
    if not vals:
        return 0.0
    s = sorted(vals)
    n = len(s)
    return s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2.0


def span(rows, begin_ev, end_ev):
    b = sorted(r["us"] for r in rows if r["event"] == begin_ev and r["us"] is not None)
    e = sorted(r["us"] for r in rows if r["event"] == end_ev and r["us"] is not None)
    if not b or not e:
        return 0.0, 0
    return (e[-1] - b[0]) / 1e6, len(b)


def _pair_intervals(rows, begin_ev, end_ev, worker=None):
    b = sorted(r["us"] for r in rows if r["event"] == begin_ev and r["us"] is not None
               and (worker is None or r["id"] == worker))
    e = sorted(r["us"] for r in rows if r["event"] == end_ev and r["us"] is not None
               and (worker is None or r["id"] == worker))
    n = min(len(b), len(e))
    return [(b[i], e[i]) for i in range(n) if e[i] >= b[i]]


def live_buffer_series(rows):
    """从 BUF_NEW/BUF_DELETE 重建任意时刻存活缓冲数量的时间线。
    新同步逻辑有 work/idle/processed 三个池,work+idle 不再是总内存,
    因此用“创建-销毁”的累计值作为真实存活缓冲数。
    返回按时间排序的 (ms, 存活缓冲数) 序列。"""
    events = []
    for r in rows:
        if r["us"] is None:
            continue
        if r["event"] == "BUF_NEW":
            events.append((r["us"], +1))
        elif r["event"] == "BUF_DELETE":
            events.append((r["us"], -1))
    events.sort(key=lambda t: t[0])
    out = []
    live = 0
    for us, delta in events:
        live += delta
        out.append((us / 1000.0, live))
    return out


def thread_stats(rows):
    """各线程忙/闲/占用率统计。
    新调度算法下工作线程同时承担 AES 与叶子 HMAC,因此 worker 拆成 aes/hash 两组。"""
    def _mk(groups):
        all_iv = [iv for _, ivs in groups for iv in ivs]
        busy = sum(e - b for b, e in all_iv) / 1e6
        span_s = (max(e for _, e in all_iv) - min(b for b, _ in all_iv)) / 1e6 if all_iv else 0.0
        occ = busy / span_s * 100.0 if span_s > 0 else 0.0
        return {
            "groups": groups,
            "busy": busy,
            "idle": span_s - busy,
            "span": span_s,
            "occupancy": occ,
            "ops": len(all_iv),
        }
    workers = sorted({r["id"] for r in rows
                      if r["id"] is not None and r["event"] in ("AES_BEGIN", "HASH_BEGIN")})
    out = {
        "read": _mk([("read", _pair_intervals(rows, "LOAD_BEGIN", "LOAD_END", None))]),
        "write": _mk([("write", _pair_intervals(rows, "WRITE_BEGIN", "WRITE_END", None))]),
    }
    for w in workers:
        out[f"worker{w}"] = _mk([
            ("aes", _pair_intervals(rows, "AES_BEGIN", "AES_END", w)),
            ("hash", _pair_intervals(rows, "HASH_BEGIN", "HASH_END", w)),
        ])
    # 过滤掉没有任何区间(未产生操作)的线程:验证模式没有写操作,不显示 write 线程
    return {name: st for name, st in out.items() if st["ops"] > 0}


def metrics(rows):
    us = [r["us"] for r in rows if r["us"] is not None]
    if not us:
        return None
    t0, t1 = min(us), max(us)
    ev = Counter(r["event"] for r in rows)

    seqs = [r["seq"] for r in rows if r["seq"] is not None and r["seq"] >= 0]
    chunks = max(seqs) + 1 if seqs else 0

    work_vals = [r["work"] for r in rows if r["work"] is not None and r["work"] >= 0]
    idle_vals = [r["idle"] for r in rows if r["idle"] is not None and r["idle"] >= 0]

    run = next((r for r in rows if r["event"] == "RUN_START"), None)
    mode, threads = "?", "?"
    if run and run.get("state"):
        st = run["state"]
        if ":" in st:
            mode, threads = st.rsplit(":", 1)
        else:
            mode = st

    created = {r["id"]: r["us"] for r in rows if r["event"] == "BUF_NEW" and r["id"] is not None}
    destroyed = {}
    for r in rows:
        if r["event"] == "BUF_DELETE" and r["id"] is not None and r["id"] not in destroyed:
            destroyed[r["id"]] = r["us"]
    buf_ids = sorted(created)
    lifetimes = [destroyed[b] - created[b] for b in buf_ids if b in destroyed]
    loaded_per_buf = Counter(r["id"] for r in rows if r["event"] == "LOADED" and r["id"] is not None)
    reuse = [loaded_per_buf.get(b, 0) - 1 for b in buf_ids]

    read_sec, _ = span(rows, "LOAD_BEGIN", "LOAD_END")
    write_sec, _ = span(rows, "WRITE_BEGIN", "WRITE_END")

    series = [(r["us"], r["work"], r["idle"], r["processed"]) for r in rows
              if r["work"] is not None and r["work"] >= 0 and r["idle"] is not None and r["idle"] >= 0]

    ts = thread_stats(rows)
    worker_count = sum(1 for k in ts if k.startswith("worker"))

    # 优先使用 SchedLog 内部维护的 live 列;旧日志无此列时回退到 BUF_NEW/BUF_DELETE 重建
    live_pts = [(r["us"], r["live"]) for r in rows
                if r["live"] is not None and r["live"] >= 0]
    if live_pts:
        mem_series = sorted((us / 1000.0, live) for us, live in live_pts)
        mem_peak_buf = max(live for _, live in live_pts)
    else:
        mem_series = live_buffer_series(rows)
        mem_peak_buf = max((live for _, live in mem_series), default=0)

    return {
        "t0": t0,
        "t1": t1,
        "mode": mode,
        "threads": str(worker_count) if worker_count else threads,
        "chunks": chunks,
        "duration": (t1 - t0) / 1e6,
        "events": ev,
        "work_peak": max(work_vals) if work_vals else 0,
        "idle_peak": max(idle_vals) if idle_vals else 0,
        "idle_mean": sum(idle_vals) / len(idle_vals) if idle_vals else 0.0,
        "created": ev.get("BUF_NEW", 0),
        "destroyed": ev.get("BUF_DELETE", 0),
        "reused": ev.get("POP_IDLE", 0),
        "avg_reuse": sum(reuse) / len(reuse) if reuse else 0.0,
        "read_sec": read_sec,
        "write_sec": write_sec,
        "lifetime_min": min(lifetimes) / 1e6 if lifetimes else 0.0,
        "lifetime_med": _median(lifetimes) / 1e6 if lifetimes else 0.0,
        "lifetime_max": max(lifetimes) / 1e6 if lifetimes else 0.0,
        "mem_peak_buf": mem_peak_buf,
        "mem_peak_mib": mem_peak_buf * BUF_MIB,
        "thread_stats": ts,
        "series": series,
        "mem_series": mem_series,
    }


def gen_file(path, size_bytes):
    chunk = bytes((i * 131 + 17) & 255 for i in range(8 * 1024 * 1024))
    with open(path, "wb") as f:
        left = size_bytes
        while left:
            n = min(len(chunk), left)
            f.write(chunk[:n])
            left -= n


def prime_cache(path):
    """顺序读一遍文件,把它尽量放进操作系统页缓存,降低后续读盘的抖动"""
    try:
        with open(path, "rb") as f:
            while f.read(8 * 1024 * 1024):
                pass
    except OSError:
        pass


def run_task(exe, mode, src, dst, key, workdir):
    if dst and os.path.exists(dst):
        os.remove(dst)
    log = os.path.join(workdir, "sched_log.csv")
    if os.path.exists(log):
        os.remove(log)
    cmd = [exe, mode, "-i", src, "-k", key, "-n"]
    if dst:
        cmd += ["-o", dst]
    subprocess.run(cmd, cwd=workdir, capture_output=True)
    return log if os.path.exists(log) else None


# ---------------------------------------------------------------------------
# SVG 绘图(零依赖)
# ---------------------------------------------------------------------------

def _legend(s, items, x, y, font=11):
    """在指定位置绘制图例,返回下一个可用的 x(防重叠的固定步长)"""
    lx = x
    for name, color in items:
        s.append(f'<rect x="{lx:.1f}" y="{y-9:.1f}" width="12" height="12" fill="{color}"/>')
        s.append(f'<text x="{lx+16:.1f}" y="{y:.1f}" font-size="{font}" fill="#333">{html.escape(name)}</text>')
        lx += 16 + max(48, len(name) * 7) + 18
    return lx


def _line_svg(series_list, width, height, title, xlabel, ylabel):
    left, right, top, bottom = 56, 16, 50, 40
    xs = [p[0] for _, _, pts in series_list for p in pts]
    ys = [p[1] for _, _, pts in series_list for p in pts]
    if not xs or not ys:
        return "<p>no data</p>"
    xmin, xmax = min(xs), max(xs)
    ymin, ymax = min(ys), max(ys)
    if xmax == xmin:
        xmax = xmin + 1
    if ymax == ymin:
        ymax = ymin + 1
    ymax = max(1, int(ymax) + 1)

    def X(x):
        return left + (x - xmin) / (xmax - xmin) * (width - left - right)

    def Y(y):
        return height - bottom - (y - ymin) / (ymax - ymin) * (height - top - bottom)

    s = [f'<svg viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg" '
         f'style="font-family:Segoe UI,Arial,sans-serif;background:#fff;border:1px solid #ddd">']
    s.append(f'<text x="{width/2}" y="16" text-anchor="middle" font-size="14" font-weight="600">{html.escape(title)}</text>')
    _legend(s, [(n, c) for n, c, _ in series_list], left, 38)
    for gy in range(0, ymax + 1):
        y = Y(gy)
        s.append(f'<line x1="{left}" y1="{y:.1f}" x2="{width-right}" y2="{y:.1f}" stroke="#eee"/>')
        s.append(f'<text x="{left-8}" y="{y+4:.1f}" text-anchor="end" font-size="11" fill="#555">{gy}</text>')
    for i in range(5):
        xt = xmin + (xmax - xmin) * i / 4
        x = X(xt)
        s.append(f'<text x="{x:.1f}" y="{height-bottom+16}" text-anchor="middle" font-size="11" fill="#555">{xt:.0f}ms</text>')
    for name, color, pts in series_list:
        pts = sorted(pts)
        d = " ".join(f"{X(x):.1f},{Y(y):.1f}" for x, y in pts)
        s.append(f'<polyline points="{d}" fill="none" stroke="{color}" stroke-width="1.6"/>')
    s.append(f'<text x="{left}" y="{height-6}" font-size="11" fill="#666">{html.escape(xlabel)}</text>')
    s.append("</svg>")
    return "".join(s)


def _mem_svg(pts, width, height, title):
    """内存占用折线图(独立图表,实线,纵轴 MiB)"""
    left, right, top, bottom = 56, 16, 50, 40
    pts = sorted(pts)
    if not pts:
        return "<p>no data</p>"
    xs = [p[0] for p in pts]
    ys = [p[1] for p in pts]
    xmin, xmax = min(xs), max(xs)
    if xmax == xmin:
        xmax = xmin + 1
    step = 16
    ymax = int((max(ys) + step - 1) // step) * step
    if ymax == 0:
        ymax = step

    def X(x):
        return left + (x - xmin) / (xmax - xmin) * (width - left - right)

    def Y(y):
        return height - bottom - y / ymax * (height - top - bottom)

    s = [f'<svg viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg" '
         f'style="font-family:Segoe UI,Arial,sans-serif;background:#fff;border:1px solid #ddd">']
    s.append(f'<text x="{width/2}" y="16" text-anchor="middle" font-size="14" font-weight="600">{html.escape(title)}</text>')
    for i in range(5):
        val = ymax * i / 4
        y = Y(val)
        s.append(f'<line x1="{left}" y1="{y:.1f}" x2="{width-right}" y2="{y:.1f}" stroke="#eee"/>')
        s.append(f'<text x="{left-8}" y="{y+4:.1f}" text-anchor="end" font-size="11" fill="#555">{int(round(val))}</text>')
    for i in range(5):
        xt = xmin + (xmax - xmin) * i / 4
        x = X(xt)
        s.append(f'<text x="{x:.1f}" y="{height-bottom+16}" text-anchor="middle" font-size="11" fill="#555">{xt:.0f}ms</text>')
    d = " ".join(f"{X(x):.1f},{Y(y):.1f}" for x, y in pts)
    s.append(f'<polyline points="{d}" fill="none" stroke="#756bb1" stroke-width="1.6"/>')
    s.append(f'<text x="{left}" y="{height-6}" font-size="11" fill="#666">MiB</text>')
    s.append("</svg>")
    return "".join(s)


def _overview_svg(sizes, thr_series, mem_series, width, height, title):
    """总览图:吞吐(左轴)与峰值内存(右轴)均为分组柱,文件大小内按模式分组"""
    left, right, top, bottom = 62, 62, 72, 48
    n = len(sizes)
    k = len(thr_series)
    thr_max = max(v for _, _, vals in thr_series for v in vals) or 1
    mem_max = max(v for _, _, vals in mem_series for v in vals) or 1
    plot_w = width - left - right
    group_w = plot_w / max(1, n)
    gap = 10
    sub_w = (group_w - gap) / 2
    bar_w = sub_w / (k + 1)

    def Y_thr(v):
        return height - bottom - v / thr_max * (height - top - bottom)

    def Y_mem(v):
        return height - bottom - v / mem_max * (height - top - bottom)

    s = [f'<svg viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg" '
         f'style="font-family:Segoe UI,Arial,sans-serif;background:#fff;border:1px solid #ddd">']
    s.append(f'<text x="{width/2}" y="16" text-anchor="middle" font-size="14" font-weight="600">{html.escape(title)}</text>')

    lx = left
    for name, color, _ in thr_series:
        s.append(f'<rect x="{lx:.1f}" y="24" width="12" height="12" fill="{color}"/>')
        s.append(f'<text x="{lx+16:.1f}" y="34" font-size="11" fill="#333">{html.escape(name)}</text>')
        lx += 16 + max(48, len(name) * 7) + 18
    s.append(f'<text x="{left}" y="54" font-size="11" fill="#666">left cluster: throughput (MiB/s)  |  right cluster: peak memory (MiB)</text>')

    for i in range(5):
        v = thr_max * i / 4
        y = Y_thr(v)
        s.append(f'<line x1="{left}" y1="{y:.1f}" x2="{width-right}" y2="{y:.1f}" stroke="#eee"/>')
        s.append(f'<text x="{left-8}" y="{y+4:.1f}" text-anchor="end" font-size="11" fill="#555">{v:.0f}</text>')
    for i in range(5):
        v = mem_max * i / 4
        y = Y_mem(v)
        s.append(f'<text x="{width-right+8}" y="{y+4:.1f}" font-size="11" fill="#555">{v:.0f}</text>')

    for ci, cat in enumerate(sizes):
        gx = left + group_w * ci
        # 吞吐簇(左,实心柱)
        for si, (name, color, vals) in enumerate(thr_series):
            v = vals[ci]
            x = gx + (si + 1) * bar_w
            y = Y_thr(v)
            s.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_w*0.85:.1f}" height="{height-bottom-y:.1f}" fill="{color}"/>')
            s.append(f'<text x="{x+bar_w*0.425:.1f}" y="{y-4:.1f}" text-anchor="middle" font-size="9" fill="#333">{v:.0f}</text>')
        # 内存簇(右,实心柱,与吞吐采用一致的柱状样式)
        mx = gx + sub_w + gap
        for si, (name, color, vals) in enumerate(mem_series):
            v = vals[ci]
            x = mx + (si + 1) * bar_w
            y = Y_mem(v)
            s.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_w*0.85:.1f}" height="{height-bottom-y:.1f}" fill="{color}"/>')
            s.append(f'<text x="{x+bar_w*0.425:.1f}" y="{y-4:.1f}" text-anchor="middle" font-size="9" fill="#333">{v:.0f}</text>')
        cx = gx + group_w / 2
        s.append(f'<text x="{cx:.1f}" y="{height-bottom+16}" text-anchor="middle" font-size="11" fill="#333">{html.escape(str(cat))}</text>')

    s.append(f'<text x="{left}" y="{height-6}" font-size="11" fill="#666">left: MiB/s, right: MiB</text>')
    s.append("</svg>")
    return "".join(s)


def _thread_color(name):
    if name.startswith("worker"):
        return "#756bb1"
    if name == "read":
        return "#2b8cbe"
    if name == "write":
        return "#f4a582"
    return "#999999"


def _group_color(label):
    """工作线程内部操作组的颜色:aes(加解密)与 hash(哈希)区分"""
    return {
        "read": "#2b8cbe",
        "write": "#f4a582",
        "aes": "#756bb1",
        "hash": "#a6ce39",
    }.get(label, "#999999")


def _occupancy_svg(threads, width, height, title):
    names = list(threads.keys())
    left, right, top, bottom = 88, 52, 34, 28
    row_h = (height - top - bottom) / max(1, len(names))
    s = [f'<svg viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg" '
         f'style="font-family:Segoe UI,Arial,sans-serif;background:#fff;border:1px solid #ddd">']
    s.append(f'<text x="{width/2}" y="16" text-anchor="middle" font-size="14" font-weight="600">{html.escape(title)}</text>')
    for i, name in enumerate(names):
        y = top + row_h * i + row_h * 0.2
        h = row_h * 0.6
        occ = threads[name]["occupancy"]
        s.append(f'<rect x="{left}" y="{y:.1f}" width="{width-left-right}" height="{h:.1f}" fill="#eee"/>')
        w = (width - left - right) * occ / 100.0
        s.append(f'<rect x="{left}" y="{y:.1f}" width="{w:.1f}" height="{h:.1f}" fill="{_thread_color(name)}"/>')
        s.append(f'<text x="{left-8}" y="{y+h/2+4:.1f}" text-anchor="end" font-size="11" fill="#333">{name}</text>')
        s.append(f'<text x="{width-right+6}" y="{y+h/2+4:.1f}" font-size="11" fill="#555">{occ:.1f}%</text>')
    s.append("</svg>")
    return "".join(s)


def _gantt_svg(threads, t0, t1, width, height, title):
    """线程忙/闲时间线甘特图:每个线程一行,红色=阻塞/空闲时间,彩色=忙区间"""
    names = list(threads.keys())
    left, right, top, bottom = 88, 52, 30, 48
    if t1 <= t0:
        t1 = t0 + 1

    def X(us):
        return left + (us - t0) / (t1 - t0) * (width - left - right)

    row_h = (height - top - bottom) / max(1, len(names))
    s = [f'<svg viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg" '
         f'style="font-family:Segoe UI,Arial,sans-serif;background:#fff;border:1px solid #ddd">']
    s.append(f'<text x="{width/2}" y="16" text-anchor="middle" font-size="14" font-weight="600">{html.escape(title)}</text>')
    for i in range(6):
        xt = t0 + (t1 - t0) * i / 5
        x = X(xt)
        s.append(f'<line x1="{x:.1f}" y1="{top}" x2="{x:.1f}" y2="{height-bottom}" stroke="#eee"/>')
        s.append(f'<text x="{x:.1f}" y="{height-bottom+16}" text-anchor="middle" font-size="11" fill="#555">{xt/1000:.0f}ms</text>')
    for i, name in enumerate(names):
        y = top + row_h * i + row_h * 0.15
        h = row_h * 0.7
        st = threads[name]
        all_iv = [iv for _, ivs in st["groups"] for iv in ivs]
        if all_iv:
            b0 = min(b for b, _ in all_iv)
            e1 = max(e for _, e in all_iv)
            s.append(f'<rect x="{X(b0):.1f}" y="{y:.1f}" width="{X(e1)-X(b0):.1f}" height="{h:.1f}" fill="{BLOCK_COLOR}"/>')
        for label, ivs in st["groups"]:
            color = _group_color(label)
            for b, e in ivs:
                s.append(f'<rect x="{X(b):.1f}" y="{y:.1f}" width="{max(1.0, X(e)-X(b)):.1f}" height="{h:.1f}" fill="{color}"/>')
        s.append(f'<text x="{left-8}" y="{y+h/2+4:.1f}" text-anchor="end" font-size="11" fill="#333">{name}</text>')
        s.append(f'<text x="{width-right+6}" y="{y+h/2+4:.1f}" font-size="11" fill="#555">{st["occupancy"]:.0f}%</text>')
    legend_items = [("read", _group_color("read")), ("write", _group_color("write")),
                    ("aes", _group_color("aes")), ("hash", _group_color("hash")),
                    ("blocked", BLOCK_COLOR)]
    lx = left
    for label, color in legend_items:
        s.append(f'<rect x="{lx:.1f}" y="{height-17:.1f}" width="10" height="10" fill="{color}"/>')
        s.append(f'<text x="{lx+13:.1f}" y="{height-7:.1f}" font-size="10" fill="#555">{label}</text>')
        lx += 13 + len(label) * 6 + 14
    s.append("</svg>")
    return "".join(s)


def html_report(results, out_path):
    sizes = [r["size"] for r in results]

    # 总览:吞吐(柱)与峰值内存(线)合并到一张双轴图
    thr_series = []
    for name, _ in MODES:
        thr_series.append((name, MODE_COLORS[name],
                           [r["mib"] / r[name]["duration"] if r.get(name) and r[name]["duration"] > 0 else 0.0
                            for r in results]))
    mem_series = []
    for name, _ in MODES:
        mem_series.append((name, MODE_COLORS[name],
                           [r[name]["mem_peak_mib"] if r.get(name) else 0.0
                            for r in results]))
    overview = _overview_svg(sizes, thr_series, mem_series, 760, 320,
                             "overview: throughput & peak memory")

    # 对比表
    rows = []
    for r in results:
        for name, _ in MODES:
            m = r.get(name)
            if not m:
                continue
            thr = r["mib"] / m["duration"] if m["duration"] > 0 else 0.0
            rows.append(
                "<tr>"
                f"<td>{html.escape(r['size'])}</td><td>{name}</td><td>{m['mode']}</td>"
                f"<td>{html.escape(str(m['threads']))}</td><td>{m['chunks']}</td><td>{m['duration']:.3f}s</td>"
                f"<td>{thr:.1f}</td><td>{m['mem_peak_mib']}</td><td>{m['work_peak']}</td><td>{m['idle_peak']}</td>"
                f"<td>{m['idle_mean']:.2f}</td><td>{m['created']}</td><td>{m['reused']}</td>"
                f"<td>{m['avg_reuse']:.2f}</td>"
                "</tr>")

    # 按文件大小分组:每个大小下依次展示 enc/dec/ver 的工作池折线图、占用率条形图、甘特图
    size_sections = []
    for r in results:
        charts = []
        for name, _ in MODES:
            m = r.get(name)
            if not m:
                continue
            pts_work = [(us / 1000.0, work) for us, work, idle, processed in m["series"]]
            pts_idle = [(us / 1000.0, idle) for us, work, idle, processed in m["series"]]
            pts_processed = [(us / 1000.0, processed) for us, work, idle, processed in m["series"]
                             if processed is not None and processed >= 0]
            pts_mem = [(us, live * BUF_MIB) for us, live in m["mem_series"]]
            charts.append(f"<h3>{name}</h3>")
            charts.append(_line_svg(
                [("loaded pool", "#2b8cbe", pts_work),
                 ("processed pool", "#756bb1", pts_processed),
                 ("idle pool", "#f4a582", pts_idle)],
                760, 250, f"{name} - loaded/processed/idle pool over time", "time(ms)", "pool size"))
            charts.append(_mem_svg(pts_mem, 760, 250, f"{name} - memory usage over time"))
            charts.append(_occupancy_svg(m["thread_stats"], 760, 210, f"{name} - thread occupancy"))
            charts.append(_gantt_svg(m["thread_stats"], m["t0"], m["t1"], 760, 210,
                                     f"{name} - thread busy/idle timeline"))
        size_sections.append(
            f'<h2>{html.escape(r["size"])}</h2>' +
            "".join(f'<div class="chart">{c}</div>' for c in charts))

    doc = f"""<!doctype html>
<html lang="zh"><head><meta charset="utf-8">
<title>Wencry 调度日志分析</title>
<style>
body{{font-family:'Segoe UI',Arial,sans-serif;margin:24px;color:#222}}
h1{{font-size:20px}} h2{{font-size:16px;margin-top:28px}}
h3{{font-size:14px;margin-top:16px;color:#555}}
.chart{{margin:12px 0}}
table{{border-collapse:collapse;font-size:13px}}
th,td{{border:1px solid #ccc;padding:5px 8px;text-align:right}}
th{{background:#f2f2f2}}
td:first-child,th:first-child{{text-align:left}}
</style></head><body>
<h1>Wencry 多线程调度日志分析(加密/解密/验证对比)</h1>
<h2>总览:吞吐与内存占用峰值(不指定 cmode,默认模式)</h2>
<div class="chart">{overview}</div>
<h2>各文件大小:调度与线程图表</h2>
{''.join(size_sections)}
<h2>指标表</h2>
<table>
<tr><th>size</th><th>task</th><th>mode</th><th>threads</th><th>chunks</th><th>duration</th>
<th>MiB/s</th><th>peak mem(MiB)</th><th>peak work</th><th>peak idle</th><th>idle mean</th><th>created</th>
<th>reused</th><th>avg reuse</th></tr>
{''.join(rows)}
</table>
</body></html>"""
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(doc)
    return out_path


def text_report(results):
    print("=" * 104)
    print(f"{'size':>8} {'task':>4} {'threads':>8} {'chunks':>6} {'memPeak':>9} {'workPeak':>8} {'idlePeak':>8} "
          f"{'idleMean':>8} {'created':>7} {'reused':>7} {'dur(s)':>7} {'MiB/s':>8}")
    print("-" * 104)
    for r in results:
        for name, _ in MODES:
            m = r.get(name)
            if not m:
                print(f"{r['size']:>8} {name:>4}  (no data)")
                continue
            thr = r["mib"] / m["duration"] if m["duration"] > 0 else 0.0
            print(f"{r['size']:>8} {name:>4} {m['threads']:>8} {m['chunks']:>6} {m['mem_peak_mib']:>9} {m['work_peak']:>8} "
                  f"{m['idle_peak']:>8} {m['idle_mean']:>8.2f} {m['created']:>7} "
                  f"{m['reused']:>7} {m['duration']:>7.3f} {thr:>8.1f}")
    print("=" * 104)


def main(argv=None):
    ap = argparse.ArgumentParser(description="集成运行(加密/解密/验证) + 日志分析 + 图表报告")
    ap.add_argument("--exe", default=os.path.join("build_log", "Release", "Wencry.exe"),
                    help="Wencry.exe 路径(需 -DLOG_SCHED=ON 编译)")
    ap.add_argument("--sizes", default="32,200,512", help="逗号分隔的输入大小(MiB)")
    ap.add_argument("--key", default=DEFAULT_KEY, help="base64 密钥")
    ap.add_argument("--out", default="sched_report", help="输出目录(日志与 HTML 报告)")
    ap.add_argument("--runs", type=int, default=5,
                    help="每种模式测量次数,去离群值后取稳定值以降低输入输出抖动(默认5)")
    ap.add_argument("--warmup", type=int, default=2,
                    help="每个大小在计时前的预热轮数(默认2,大文件建议>=2)")
    args = ap.parse_args(argv)

    exe = os.path.abspath(args.exe)
    if not os.path.exists(exe):
        print(f"exe not found: {exe}", file=sys.stderr)
        print("build with -DLOG_SCHED=ON first, or pass --exe", file=sys.stderr)
        return 2

    out = os.path.abspath(args.out)
    os.makedirs(out, exist_ok=True)
    sizes = [int(x) for x in args.sizes.split(",") if x.strip()]
    results = []

    for mib in sizes:
        label = f"{mib}MiB"
        src = os.path.join(out, "in.bin")
        enc = os.path.join(out, "in.wenc")
        dec = os.path.join(out, "in.out")
        gen_file(src, mib * 1024 * 1024)
        prime_cache(src)  # 生成后先读一遍,保证首次预热也不是冷读
        entry = {"size": label, "mib": mib}
        # 预热多轮(丢弃结果):大文件只预热一轮仍可能有缓存/写回抖动
        for _ in range(max(1, args.warmup)):
            for name, mode in MODES:
                if name == "enc":
                    task_src, dst = src, enc
                elif name == "dec":
                    task_src, dst = enc, dec
                else:
                    task_src, dst = enc, None
                run_task(exe, mode, task_src, dst, args.key, out)
        for name, mode in MODES:
            if name == "enc":
                task_src, dst = src, enc
            elif name == "dec":
                task_src, dst = enc, dec
            else:
                task_src, dst = enc, None

            # 多次测量,去掉最快/最慢的离群值后取最接近均值的一次,抑制 I/O 抖动
            candidates = []
            for i in range(max(1, args.runs)):
                log = run_task(exe, mode, task_src, dst, args.key, out)
                if log is None:
                    continue
                tmp = os.path.join(out, f"sched_log_{mib}MiB_{name}_run{i}.csv")
                shutil.move(log, tmp)
                candidates.append(tmp)

            if not candidates:
                print(f"[{label}/{name}] no log produced", file=sys.stderr)
                entry[name] = None
                continue

            parsed = []
            for p in candidates:
                m = metrics(load_csv(p))
                if m is not None:
                    parsed.append((m["duration"], p, m))
            if not parsed:
                entry[name] = None
                for p in candidates:
                    if os.path.exists(p):
                        os.remove(p)
                continue

            parsed.sort(key=lambda t: t[0])
            trimmed = parsed[1:-1] if len(parsed) >= 5 else parsed
            target = sum(t[0] for t in trimmed) / len(trimmed)
            _, best_path, best_m = min(trimmed, key=lambda t: abs(t[0] - target))
            final_path = os.path.join(out, f"sched_log_{mib}MiB_{name}.csv")
            shutil.move(best_path, final_path)
            entry[name] = best_m
            for _, p, _ in parsed:
                if p != best_path and os.path.exists(p):
                    os.remove(p)
            print(f"[{label}/{name}] done", flush=True)
        for p in (src, enc, dec):
            if os.path.exists(p):
                os.remove(p)
        results.append(entry)

    text_report(results)
    report = html_report(results, os.path.join(out, "report.html"))
    print(f"\nHTML report: {report}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
