"""目标范围校验：默认只允许回环与私有网段。

这不是保守，是让仓库的性质停留在「授权测试工具」。
要测公网资产，必须显式传 allow_external，并由调用方自己确认授权。
"""
from __future__ import annotations

import ipaddress
import socket


class ScopeError(ValueError):
    """目标不在允许范围内。"""


def resolve(host: str) -> list[str]:
    """把主机名解析成 IP 列表；解析失败按错误处理，不猜。"""
    try:
        ipaddress.ip_address(host)
        return [host]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise ScopeError(f"无法解析主机：{host}") from exc
    return sorted({info[4][0] for info in infos})


def assert_allowed(host: str, allow_external: bool = False) -> list[str]:
    """校验目标，返回解析后的 IP 列表。"""
    if not host or host.strip() == "":
        raise ScopeError("目标不能为空")

    addresses = resolve(host.strip())
    if allow_external:
        return addresses

    for raw in addresses:
        ip = ipaddress.ip_address(raw)
        if not (ip.is_private or ip.is_loopback):
            raise ScopeError(
                f"{host} 解析到公网地址 {raw}，默认拒绝。"
                "确需测试请显式传 allow_external=true，并自行确认授权范围。"
            )
    return addresses
