"""Normalize supplied OpenWrt data into a bounded, credential-free snapshot."""
from __future__ import annotations
import ipaddress, json, math, re
from datetime import datetime, timezone

MAX_INPUT_BYTES=1024*1024
MAX_INTERFACES=256
MAX_RADIOS=256
MAX_ASSOCIATIONS=8192
MAX_ROUTES=2048
BANDS={"2.4GHz","5GHz","6GHz"}
WIDTHS={20,40,80,160,320}
MAC=re.compile(r"^[0-9A-F]{2}(?::[0-9A-F]{2}){5}$")


def _list(value, field, limit):
    if not isinstance(value,list) or len(value)>limit:
        raise ValueError(f"{field} must be a list containing no more than {limit} records")
    return value


def _text(value, field, maximum=256, required=False):
    if value is None:
        if required: raise ValueError(f"{field} is required")
        return None
    if not isinstance(value,str): raise ValueError(f"{field} must be a string")
    value=value.strip()
    if required and not value: raise ValueError(f"{field} is required")
    if len(value)>maximum: raise ValueError(f"{field} exceeds the {maximum}-character limit")
    return value or None


def _number(value, field, minimum=None, maximum=None):
    if value is None: return None
    if isinstance(value,bool): raise ValueError(f"{field} must be a finite number")
    try: parsed=float(value)
    except (TypeError,ValueError) as error: raise ValueError(f"{field} must be numeric") from error
    if not math.isfinite(parsed): raise ValueError(f"{field} must be a finite number")
    if minimum is not None and parsed<minimum or maximum is not None and parsed>maximum:
        raise ValueError(f"{field} is outside the supported range")
    return parsed


def _timestamp(value):
    if not isinstance(value,str) or not value.strip():
        raise ValueError("captured_at must be a timezone-aware ISO-8601 timestamp")
    try: parsed=datetime.fromisoformat(value.strip().replace("Z","+00:00"))
    except ValueError as error: raise ValueError("captured_at must be a timezone-aware ISO-8601 timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("captured_at must include a timezone offset")
    return parsed.astimezone(timezone.utc).isoformat()


def _integer(value, field, minimum=0, maximum=9007199254740991):
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field} must be an integer")
    if not minimum <= value <= maximum:
        raise ValueError(f"{field} is outside the supported range")
    return value


def _ip_interface(item, field, version):
    if not isinstance(item,dict): raise ValueError(f"{field} entries must be objects")
    address=item.get("address")
    mask=item.get("mask")
    if not isinstance(address,str): raise ValueError(f"{field}.address must be an IP address")
    try:
        if mask is None: parsed=ipaddress.ip_interface(address)
        else:
            if isinstance(mask,bool) or not isinstance(mask,int) or not 0<=mask<=(32 if version==4 else 128): raise ValueError
            parsed=ipaddress.ip_interface(f"{address}/{mask}")
    except ValueError as error: raise ValueError(f"{field} contains an invalid IPv{version} interface address") from error
    if parsed.version!=version: raise ValueError(f"{field} must contain IPv{version} addresses")
    return str(parsed)


def _band(frequency, supplied):
    if supplied is not None:
        band=_text(supplied,"wireless.band",maximum=16)
        if band not in BANDS: raise ValueError(f"wireless.band must be one of {sorted(BANDS)}")
        return band
    if frequency is None: return None
    if 2400<=frequency<2500: return "2.4GHz"
    if 4900<=frequency<5925: return "5GHz"
    if 5925<=frequency<=7125: return "6GHz"
    return None


def normalize_snapshot(payload):
    if not isinstance(payload,dict): raise ValueError("payload must be an object")
    try: encoded=json.dumps(payload,ensure_ascii=False,separators=(",",":"),allow_nan=False)
    except (TypeError,ValueError) as error: raise ValueError("OpenWrt snapshot must contain JSON-compatible finite values") from error
    if len(encoded.encode("utf-8"))>MAX_INPUT_BYTES: raise ValueError(f"OpenWrt snapshot exceeds the {MAX_INPUT_BYTES}-byte input limit")

    captured_at=_timestamp(payload.get("captured_at"))
    board=payload.get("board",{})
    if not isinstance(board,dict): raise ValueError("board must be an object")
    release=board.get("release",{})
    if not isinstance(release,dict): raise ValueError("board.release must be an object")
    normalised_board={
        "model":_text(board.get("model"),"board.model"),
        "board_name":_text(board.get("board_name"),"board.board_name"),
        "hostname":_text(board.get("hostname"),"board.hostname",64),
        "kernel":_text(board.get("kernel"),"board.kernel"),
        "distribution":_text(release.get("distribution"),"board.release.distribution"),
        "version":_text(release.get("version"),"board.release.version",64),
        "revision":_text(release.get("revision"),"board.release.revision",128),
        "target":_text(release.get("target"),"board.release.target",128),
    }

    interfaces=[]
    names=set()
    for i,record in enumerate(_list(payload.get("interfaces",[]),"interfaces",MAX_INTERFACES)):
        if not isinstance(record,dict): raise ValueError(f"interfaces[{i}] must be an object")
        name=_text(record.get("interface",record.get("name")),f"interfaces[{i}].interface",32,True)
        if name in names: raise ValueError("interface names must be unique")
        names.add(name)
        v4=_list(record.get("ipv4-address",record.get("ipv4_addresses",[])),f"interfaces[{i}].ipv4-address",32)
        v6=_list(record.get("ipv6-address",record.get("ipv6_addresses",[])),f"interfaces[{i}].ipv6-address",32)
        interfaces.append({
            "interface":name,
            "device":_text(record.get("device"),f"interfaces[{i}].device",32),
            "protocol":_text(record.get("proto",record.get("protocol")),f"interfaces[{i}].protocol",32),
            "up":record.get("up") if isinstance(record.get("up"),bool) else None,
            "ipv4_addresses":[_ip_interface(x,f"interfaces[{i}].ipv4-address",4) for x in v4],
            "ipv6_addresses":[_ip_interface(x,f"interfaces[{i}].ipv6-address",6) for x in v6],
        })

    radios=[]
    radio_names=set()
    for i,record in enumerate(_list(payload.get("wireless",[]),"wireless",MAX_RADIOS)):
        if not isinstance(record,dict): raise ValueError(f"wireless[{i}] must be an object")
        name=_text(record.get("interface",record.get("ifname")),f"wireless[{i}].interface",32,True)
        if name in radio_names: raise ValueError("wireless interface names must be unique")
        radio_names.add(name)
        bssid=record.get("bssid")
        if bssid is not None:
            bssid=str(bssid).replace("-",":").upper()
            if not MAC.fullmatch(bssid): raise ValueError(f"wireless[{i}].bssid must be a valid BSSID")
        frequency=_number(record.get("frequency_mhz",record.get("frequency")),f"wireless[{i}].frequency_mhz",2000,8000)
        channel=record.get("channel")
        if channel is not None and (isinstance(channel,bool) or not isinstance(channel,int) or not 1<=channel<=233):
            raise ValueError(f"wireless[{i}].channel must be an integer from 1 to 233")
        width=record.get("channel_width_mhz",record.get("width"))
        if width is not None and (isinstance(width,bool) or not isinstance(width,int) or width not in WIDTHS):
            raise ValueError(f"wireless[{i}].channel_width_mhz must be a supported channel width")
        security=record.get("security")
        encryption=record.get("encryption")
        if security is None and isinstance(encryption,dict): security=encryption.get("description")
        radios.append({
            "interface":name,"ssid":_text(record.get("ssid"),f"wireless[{i}].ssid",64),
            "bssid":bssid,"band":_band(frequency,record.get("band")),"channel":channel,
            "frequency_mhz":frequency,"channel_width_mhz":width,
            "tx_power_dbm":_number(record.get("txpower_dbm",record.get("txpower")),f"wireless[{i}].txpower_dbm",-20,60),
            "signal_dbm":_number(record.get("signal"),f"wireless[{i}].signal",-150,0),
            "noise_dbm":_number(record.get("noise"),f"wireless[{i}].noise",-150,0),
            "security":_text(security,f"wireless[{i}].security",80),
            "up":record.get("up") if isinstance(record.get("up"),bool) else None,
        })

    system_health = payload.get("system_health")
    if system_health is not None:
        if not isinstance(system_health, dict):
            raise ValueError("system_health must be an object")
        uptime = _integer(system_health.get("uptime_seconds"), "system_health.uptime_seconds")
        if uptime is None:
            raise ValueError("system_health.uptime_seconds is required")
        raw_load = system_health.get("load_average")
        if not isinstance(raw_load, dict):
            raise ValueError("system_health.load_average must be an object")
        load_average = {}
        for period in ("1m", "5m", "15m"):
            value = _number(raw_load.get(period), f"system_health.load_average.{period}", 0, 1000000)
            if value is None:
                raise ValueError(f"system_health.load_average.{period} is required")
            load_average[period] = value

        def health_bytes(name, required):
            value = system_health.get(name)
            if not isinstance(value, dict):
                raise ValueError(f"system_health.{name} must be an object")
            result = {}
            for field in ("total", "free", "shared", "buffered", "available", "cached"):
                parsed = _integer(value.get(field), f"system_health.{name}.{field}")
                if parsed is None and field in required:
                    raise ValueError(f"system_health.{name}.{field} is required")
                if parsed is not None:
                    result[field] = parsed
            if result.get("total") is not None and result.get("free") is not None:
                if result["free"] > result["total"]:
                    raise ValueError(f"system_health.{name}.free cannot exceed total")
            return result

        system_health = {
            "uptime_seconds": uptime,
            "load_average": load_average,
            "memory_bytes": health_bytes("memory_bytes", ("total", "free")),
            "swap_bytes": health_bytes("swap_bytes", ("total", "free")),
        }

    associations=[]
    seen=set()
    invalid=0
    raw_associations=_list(payload.get("associations",[]),"associations",MAX_ASSOCIATIONS)
    for i,record in enumerate(raw_associations):
        if not isinstance(record,dict): raise ValueError(f"associations[{i}] must be an object")
        interface=_text(record.get("interface",record.get("ifname")),f"associations[{i}].interface",32)
        stations=record.get("stations")
        if stations is None: stations=[record]
        for j,station in enumerate(_list(stations,f"associations[{i}].stations",MAX_ASSOCIATIONS)):
            if not isinstance(station,dict): raise ValueError(f"associations[{i}].stations[{j}] must be an object")
            mac=str(station.get("mac",station.get("macaddr",""))).replace("-",":").upper()
            if not MAC.fullmatch(mac):
                invalid+=1
                continue
            identity=(interface,mac)
            if identity in seen: raise ValueError("client MAC/interface association pairs must be unique")
            seen.add(identity)
            tx=station.get("tx")
            rx=station.get("rx")
            associations.append({
                "interface":interface,"client_mac":mac,
                "signal_dbm":_number(station.get("signal"),"association.signal",-150,0),
                "tx_rate_mbps":_number(station.get("tx_rate_mbps",tx.get("rate") if isinstance(tx,dict) else None),"association.tx_rate_mbps",0,100000),
                "rx_rate_mbps":_number(station.get("rx_rate_mbps",rx.get("rate") if isinstance(rx,dict) else None),"association.rx_rate_mbps",0,100000),
            })
    if len(associations)>MAX_ASSOCIATIONS: raise ValueError(f"associations may contain no more than {MAX_ASSOCIATIONS} stations")

    routes=[]
    for i,route in enumerate(_list(payload.get("routes",[]),"routes",MAX_ROUTES)):
        if not isinstance(route,dict): raise ValueError(f"routes[{i}] must be an object")
        target=_text(route.get("target",route.get("dest","0.0.0.0/0")),f"routes[{i}].target",64,True)
        try: destination=str(ipaddress.ip_network(target,strict=False))
        except ValueError as error: raise ValueError(f"routes[{i}].target must be an IP network") from error
        gateway=route.get("nexthop",route.get("gateway"))
        if gateway is not None:
            try: gateway=str(ipaddress.ip_address(gateway))
            except ValueError as error: raise ValueError(f"routes[{i}].gateway must be an IP address") from error
        metric=route.get("metric")
        if metric is not None and (isinstance(metric,bool) or not isinstance(metric,int) or not 0<=metric<=65535):
            raise ValueError(f"routes[{i}].metric must be an integer from 0 to 65535")
        routes.append({"target":destination,"gateway":gateway,
                       "device":_text(route.get("device",route.get("interface")),f"routes[{i}].device",32),
                       "metric":metric})

    return {
        "adapter_id":"openwrt","captured_at":captured_at,"board":normalised_board,
        "interfaces":interfaces,"wireless_radios":radios,"associations":associations,"routes":routes,
        **({"system_health":system_health} if system_health is not None else {}),
        "summary":{"interface_count":len(interfaces),"wireless_radio_count":len(radios),
                   "association_count":len(associations),"invalid_association_count":invalid,"route_count":len(routes)},
        "note":"Normalised from caller-supplied OpenWrt data. Unrecognised and credential-like fields are not copied; no router connection is opened and raw input is not persisted.",
    }
