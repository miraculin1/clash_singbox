import base64
import json
import re
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, unquote, urlparse


def read_subscription_from_file(file_path: str) -> str:
    """从文件读取订阅内容"""
    with open(file_path, "r", encoding="utf-8") as file:
        return file.read().strip()


def decode_subscription_text(subscription_data: str) -> str:
    """尝试将订阅内容作为 Base64 解码，失败则直接返回原始内容"""
    if not subscription_data:
        return ""

    compact_data = "".join(subscription_data.split())
    try:
        padded = compact_data + "=" * (-len(compact_data) % 4)
        decoded_bytes = base64.b64decode(padded, validate=True)
        decoded_text = decoded_bytes.decode("utf-8", errors="replace")
        if "://" in decoded_text or "\n" in decoded_text:
            return decoded_text
    except Exception:
        pass

    return subscription_data


def sanitize_tag(raw_tag: Optional[str], fallback_prefix: str, index: int) -> str:
    """生成 sing-box 可用的 tag，避免空格和特殊字符"""
    label = (unquote(raw_tag or "").strip()) or f"{fallback_prefix}-{index:02d}"
    normalized = re.sub(r"\s+", "-", label)
    if not normalized.strip("-"):
        normalized = f"{fallback_prefix}-{index:02d}"
    return normalized


def bool_from_param(value: Optional[str]) -> bool:
    if value is None:
        return False
    return value.lower() in {"1", "true", "yes", "on"}


def parse_trojan_uri(uri: str, index: int) -> Dict[str, Any]:
    parsed = urlparse(uri)
    if not parsed.username or not parsed.hostname:
        raise ValueError("Trojan URI 缺少密码或域名")

    query = parse_qs(parsed.query)
    tag = sanitize_tag(parsed.fragment, "trojan", index)
    tls_server_name = query.get("sni") or query.get("peer")
    allow_insecure = query.get("allowInsecure") or query.get("allow_insecure")

    outbound: Dict[str, Any] = {
        "tag": tag,
        "type": "trojan",
        "server": parsed.hostname,
        "server_port": parsed.port or 443,
        "password": parsed.username,
        "tls": {
            "enabled": True,
            "insecure": bool_from_param(allow_insecure[0]) if allow_insecure else False,
        },
    }

    if tls_server_name:
        outbound["tls"]["server_name"] = tls_server_name[0]

    transport_type = query.get("type", [None])[0]
    if transport_type:
        transport: Dict[str, Any] = {"type": transport_type}
        if transport_type == "ws":
            if "path" in query:
                transport["path"] = query["path"][0]
            host = query.get("host")
            if host:
                transport["headers"] = {"Host": host[0]}
        elif transport_type == "grpc":
            service_name = query.get("serviceName") or query.get("service_name")
            if service_name:
                transport["service_name"] = service_name[0]
        outbound["transport"] = transport

    return outbound


def parse_vmess_uri(uri: str, index: int) -> Dict[str, Any]:
    payload_part, _, fragment = uri.partition("#")
    payload = payload_part.split("://", 1)[1]
    padded = payload + "=" * (-len(payload) % 4)
    decoded_json = base64.b64decode(padded).decode("utf-8", errors="replace")
    data = json.loads(decoded_json)

    server = data.get("add")
    uuid = data.get("id")
    if not server or not uuid:
        raise ValueError("vmess 节点缺少必要字段")

    tag = sanitize_tag(fragment or data.get("ps"), "vmess", index)
    outbound: Dict[str, Any] = {
        "tag": tag,
        "type": "vmess",
        "server": server,
        "server_port": int(data.get("port", 443)),
        "uuid": uuid,
        "alter_id": int(data.get("aid", 0)),
        "security": data.get("scy", "auto"),
    }

    network = (data.get("net") or "tcp").lower()
    if network != "tcp":
        transport: Dict[str, Any] = {"type": network}
        if network == "ws":
            host = data.get("host")
            path = data.get("path") or "/"
            transport["path"] = path
            if host:
                transport["headers"] = {"Host": host}
        elif network == "grpc":
            if data.get("path"):
                transport["service_name"] = data["path"].lstrip("/")
        outbound["transport"] = transport

    if data.get("tls", "").lower() == "tls":
        outbound["tls"] = {
            "enabled": True,
            "server_name": data.get("sni") or data.get("host") or server,
            "insecure": bool_from_param(str(data.get("allowInsecure", "0"))),
        }

    return outbound


def parse_vless_uri(uri: str, index: int) -> Dict[str, Any]:
    parsed = urlparse(uri)
    if not parsed.username or not parsed.hostname:
        raise ValueError("vless 节点缺少 UUID 或域名")

    query = parse_qs(parsed.query)
    tag = sanitize_tag(parsed.fragment, "vless", index)
    outbound: Dict[str, Any] = {
        "tag": tag,
        "type": "vless",
        "server": parsed.hostname,
        "server_port": parsed.port or 443,
        "uuid": parsed.username,
    }

    flow = query.get("flow")
    if flow:
        outbound["flow"] = flow[0]

    security = (query.get("security", ["tls"])[0] or "tls").lower()
    tls: Dict[str, Any] = {"enabled": security in {"tls", "reality"}}
    if security == "reality":
        tls["reality"] = {
            "enabled": True,
            "public_key": query.get("pbk", [""])[0],
            "short_id": query.get("sid", [""])[0],
        }
    if query.get("sni"):
        tls["server_name"] = query["sni"][0]
    if query.get("allowInsecure"):
        tls["insecure"] = bool_from_param(query["allowInsecure"][0])

    outbound["tls"] = tls

    transport_type = query.get("type", [None])[0]
    if transport_type:
        transport: Dict[str, Any] = {"type": transport_type}
        if transport_type == "ws":
            if "path" in query:
                transport["path"] = query["path"][0]
            host = query.get("host")
            if host:
                transport["headers"] = {"Host": host[0]}
        elif transport_type == "grpc":
            service_name = query.get("serviceName") or query.get("service_name")
            if service_name:
                transport["service_name"] = service_name[0]
        outbound["transport"] = transport

    return outbound


def parse_shadowsocks_uri(uri: str, index: int) -> Dict[str, Any]:
    payload_part, _, fragment = uri.partition("#")
    tag = sanitize_tag(fragment, "ss", index)

    plugin = None
    if "?" in payload_part:
        payload_part, plugin_part = payload_part.split("?", 1)
        for kv in plugin_part.split("&"):
            if kv.startswith("plugin="):
                plugin = unquote(kv.split("=", 1)[1])
                break

    payload = payload_part.split("://", 1)[1]
    if "@" not in payload:
        decoded = base64.b64decode(payload + "=" * (-len(payload) % 4)).decode("utf-8")
        userinfo, server_part = decoded.rsplit("@", 1)
    else:
        userinfo, server_part = payload.split("@", 1)

    method, password = userinfo.split(":", 1)
    server, port = server_part.split(":", 1)

    outbound: Dict[str, Any] = {
        "tag": tag,
        "type": "shadowsocks",
        "server": server,
        "server_port": int(port),
        "method": method,
        "password": password,
    }

    if plugin:
        outbound["plugin"] = plugin

    return outbound


def parse_subscription_data(subscription_data: str) -> List[Dict[str, Any]]:
    decoded_text = decode_subscription_text(subscription_data)
    lines = [line.strip() for line in decoded_text.splitlines() if line.strip()]

    outbounds: List[Dict[str, Any]] = []
    for index, line in enumerate(lines, start=1):
        if "://" not in line:
            continue
        scheme = line.split("://", 1)[0].lower()
        try:
            if scheme == "trojan":
                outbound = parse_trojan_uri(line, index)
            elif scheme == "vmess":
                outbound = parse_vmess_uri(line, index)
            elif scheme == "vless":
                outbound = parse_vless_uri(line, index)
            elif scheme == "ss":
                outbound = parse_shadowsocks_uri(line, index)
            else:
                print(f"⚠️ 未识别的节点类型：{scheme}")
                continue
        except Exception as exc:
            print(f"⚠️ 解析第 {index} 行失败：{exc}")
            continue

        outbounds.append(outbound)

    return outbounds


def main() -> None:
    file_path = input("请输入订阅内容文件路径：").strip()

    try:
        print("📥 正在读取订阅数据...")
        subscription_data = read_subscription_from_file(file_path)
        print("✅ 订阅内容读取完成！")

        print("🧳 正在解析并转换为 sing-box outbounds...")
        outbounds = parse_subscription_data(subscription_data)

        if not outbounds:
            print("⚠️ 未能解析出任何节点，请检查订阅内容。")
            return

        print("✅ Sing-Box outbounds 配置：")
        print(json.dumps(outbounds, indent=2, ensure_ascii=False))

    except Exception as error:
        print(f"❌ 出错: {error}")


if __name__ == "__main__":
    main()
