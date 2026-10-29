"""TCP 全连接扫描。

用 connect_ex 而不是 connect：前者返回错误码、不抛异常，
批量扫描时不用给每次尝试套 try/except。
只做全连接，不做 SYN——原始套接字要管理员权限，跨平台行为也不一致。
"""
from __future__ import annotations

import socket
import time
from concurrent.futures import ThreadPoolExecutor

from ..scope import assert_allowed

MAX_PORTS = 1024


def parse_ports(spec: str) -> list[int]:
    """支持 "22,80,8000-8010" 这种写法。"""
    ports: set[int] = set()
    for chunk in spec.replace(" ", "").split(","):
        if not chunk:
            continue
        if "-" in chunk:
            left, right = chunk.split("-", 1)
            start, end = int(left), int(right)
            if start > end:
                start, end = end, start
            ports.update(range(start, end + 1))
        else:
            ports.add(int(chunk))
    invalid = [p for p in ports if not 0 < p < 65536]
    if invalid:
        raise ValueError(f"端口越界：{invalid[:5]}")
    if len(ports) > MAX_PORTS:
        raise ValueError(f"一次最多 {MAX_PORTS} 个端口，当前 {len(ports)}")
    return sorted(ports)


def _scan_one(host: str, port: int, timeout: float) -> dict:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    started = time.perf_counter()
    try:
        code = sock.connect_ex((host, port))
    except OSError:
        code = -1
    finally:
        sock.close()
    return {
        "port": port,
        "open": code == 0,
        "latency_ms": round((time.perf_counter() - started) * 1000, 1),
    }


def scan(
    host: str,
    ports: str = "22,80,443",
    timeout: float = 1.0,
    workers: int = 100,
    allow_external: bool = False,
) -> dict:
    assert_allowed(host, allow_external)
    port_list = parse_ports(ports)
    workers = max(1, min(workers, 200))

    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(lambda p: _scan_one(host, p, timeout), port_list))

    open_ports = [r for r in results if r["open"]]
    return {
        "host": host,
        "scanned": len(results),
        "open": open_ports,
        "closed": len(results) - len(open_ports),
        "timeout": timeout,
        "note": "仅 TCP 全连接扫描，未做 SYN/UDP；短超时可能把慢响应端口判为关闭。",
    }
