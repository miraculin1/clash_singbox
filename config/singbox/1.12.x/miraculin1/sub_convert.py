import argparse
import base64
import json
import re
import sys
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, unquote, urlparse
from urllib.request import Request, urlopen


def download_subscription_from_url(url: str) -> str:
    """从 URL 下载订阅内容"""
    request = Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 (compatible; sub-convert/1.0)",
            "Accept": "*/*",
        },
    )
    with urlopen(request, timeout=30) as response:
        data = response.read()
    return data.decode("utf-8", errors="replace").strip()


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


def normalize_transport_type(value: Optional[str]) -> Optional[str]:
    """过滤 sing-box 不需要显式声明的默认传输类型。"""
    if not value:
        return None
    transport_type = value.lower()
    if transport_type in {"tcp", "raw"}:
        return None
    return transport_type


def decode_base64_text(value: str) -> str:
    padded = value + "=" * (-len(value) % 4)
    return base64.b64decode(padded).decode("utf-8", errors="replace")


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

    transport_type = normalize_transport_type(query.get("type", [None])[0])
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

    network = normalize_transport_type(data.get("net") or "tcp")
    if network:
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
        utls_fingerprint = (
            query.get("fp")
            or query.get("fingerprint")
            or query.get("client-fingerprint")
            or ["chrome"]
        )[0]
        tls["utls"] = {
            "enabled": True,
            "fingerprint": utls_fingerprint or "chrome",
        }
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

    transport_type = normalize_transport_type(query.get("type", [None])[0])
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
        decoded = decode_base64_text(payload)
        userinfo, server_part = decoded.rsplit("@", 1)
    else:
        userinfo, server_part = payload.split("@", 1)
        if "%" in userinfo:
            userinfo = unquote(userinfo)
        else:
            try:
                userinfo = decode_base64_text(userinfo)
            except Exception:
                pass

    method, separator, password = userinfo.partition(":")
    if not separator:
        raise ValueError("Shadowsocks 节点缺少加密方法或密码")
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


def parse_hysteria2_uri(uri: str, index: int) -> Dict[str, Any]:
    parsed = urlparse(uri)
    if not parsed.hostname:
        raise ValueError("hysteria2 节点缺少域名")

    query = parse_qs(parsed.query)
    tag = sanitize_tag(parsed.fragment, "hysteria2", index)

    password = unquote(parsed.username) if parsed.username else ""
    if not password:
        password_values = query.get("password") or query.get("auth")
        if password_values and password_values[0]:
            password = password_values[0]
    if not password:
        raise ValueError("hysteria2 节点缺少认证密码")

    outbound: Dict[str, Any] = {
        "tag": tag,
        "type": "hysteria2",
        "server": parsed.hostname,
        "server_port": parsed.port or 443,
        "password": password,
        "tls": {
            "enabled": True,
            "insecure": False,
        },
    }

    server_name = query.get("sni")
    if server_name and server_name[0]:
        outbound["tls"]["server_name"] = server_name[0]

    insecure = query.get("insecure") or query.get("allowInsecure")
    if insecure:
        outbound["tls"]["insecure"] = bool_from_param(insecure[0])

    obfs = query.get("obfs")
    if obfs and obfs[0]:
        obfs_config: Dict[str, Any] = {"type": obfs[0]}
        obfs_password = query.get("obfs-password") or query.get("obfs_password")
        if obfs_password and obfs_password[0]:
            obfs_config["password"] = obfs_password[0]
        outbound["obfs"] = obfs_config

    return outbound


def rebuild_config_with_subscription(
    config: Dict[str, Any], subscription_outbounds: List[Dict[str, Any]]
) -> Dict[str, Any]:
    if not subscription_outbounds:
        raise ValueError("订阅中没有可用节点，无法生成完整配置")

    result = json.loads(json.dumps(config))
    existing_outbounds = result.get("outbounds")
    if not isinstance(existing_outbounds, list):
        raise ValueError("config.json 中缺少有效的 outbounds 数组")

    selector = None
    preserved_outbounds: List[Dict[str, Any]] = []
    for outbound in existing_outbounds:
        if not isinstance(outbound, dict):
            continue
        outbound_type = outbound.get("type")
        if outbound_type == "selector" and outbound.get("tag") == "select-proxy":
            selector = json.loads(json.dumps(outbound))
            continue
        if outbound_type in {"direct", "block"}:
            preserved_outbounds.append(json.loads(json.dumps(outbound)))

    if selector is None:
        selector = {
            "tag": "select-proxy",
            "type": "selector",
        }

    selector["outbounds"] = [outbound["tag"] for outbound in subscription_outbounds]
    selector["default"] = subscription_outbounds[0]["tag"]

    result["outbounds"] = [
        *subscription_outbounds,
        selector,
        *preserved_outbounds,
    ]
    return result


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
            elif scheme in {"hysteria2", "hy2"}:
                outbound = parse_hysteria2_uri(line, index)
            else:
                print(f"⚠️ 未识别的节点类型：{scheme}")
                continue
        except Exception as exc:
            print(f"⚠️ 解析第 {index} 行失败：{exc}")
            continue

        outbounds.append(outbound)

    return outbounds


def read_json_file(file_path: str) -> Dict[str, Any]:
    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)


def write_json_file(file_path: str, content: Any) -> None:
    with open(file_path, "w", encoding="utf-8") as file:
        json.dump(content, file, indent=2, ensure_ascii=False)
        file.write("\n")


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="下载订阅并转换为 sing-box outbounds 或完整配置"
    )
    parser.add_argument("-u", "--url", required=True, help="订阅 URL")
    parser.add_argument(
        "-m",
        "--mode",
        choices=["outbounds", "config"],
        default="outbounds",
        help="输出内容类型：outbounds 或 config（默认 outbounds）",
    )
    parser.add_argument(
        "-t",
        "--target",
        choices=["file", "stdout"],
        default="file",
        help="输出目标：写入文件或打印到标准输出（默认 file）",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="./out.json",
        help="输出文件路径（默认 ./out.json，仅 target=file 时生效）",
    )
    parser.add_argument(
        "-c",
        "--config",
        help="基础 config.json 路径（mode=config 时必填）",
    )
    return parser


def main() -> int:
    parser = build_argument_parser()
    args = parser.parse_args()
    if args.mode == "config" and not args.config:
        parser.error("--mode config 时必须提供 --config")

    try:
        print("📥 正在下载订阅数据...")
        subscription_data = download_subscription_from_url(args.url)
        print("✅ 订阅内容下载完成！")

        print("🧳 正在解析并转换为 sing-box outbounds...")
        outbounds = parse_subscription_data(subscription_data)

        if not outbounds:
            print("⚠️ 未能解析出任何节点，请检查订阅内容。")
            return 1

        output_content: Any = outbounds
        if args.mode == "config":
            print("🧩 正在生成完整 sing-box 配置...")
            config = read_json_file(args.config)
            output_content = rebuild_config_with_subscription(config, outbounds)

        if args.target == "stdout":
            print(json.dumps(output_content, indent=2, ensure_ascii=False))
        else:
            write_json_file(args.output, output_content)
            print(f"✅ 输出已写入：{args.output}")

    except Exception as error:
        print(f"❌ 出错: {error}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
