# -*- coding: utf-8 -*-
import sys, os, json, time, uuid, random, asyncio, base64, struct, ssl, hmac, hashlib, string
import aiohttp
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google_play_scraper import app as play_scraper
from protobuf_decoder.protobuf_decoder import Parser

AES_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
AES_IV  = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
KEYSTREAM = bytes([0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30])
HEX_KEY = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
API_KEY = HEX_KEY.encode()

REGION_LANG = {"ME":"ar","IND":"hi","ID":"id","VN":"vi","TH":"th","BD":"bn",
               "PK":"ur","TW":"zh","RU":"ru","SAC":"es","BR":"pt","NA":"pt",
               "SG":"pt","US":"pt"}

GGRE_RAW = bytes.fromhex(
    "47475245010101006d020000b260ee08e1f86b4c57f9c70f86bba26ed5d1436bcf52e142db3249d905eded757764991ca31a8373cdd26eab91b80f3f1f6f262f4f10b895d7b6937ddba30a27197453890e9da49373f736c679b8254e2f8e1623e91084a5fdd5374fe478ff99e010834553fddeb0bec4018d142e49df9bb236675b67e852f92a43586f7a7d4d0d7a197a1d4da32714dab4d069ad53214e2c33b3877420a12459738c4c619cbd815fa878bbd104776bb3e1ac7818d5397b04a666ac57f682763ff2df31bc2f846ddc7904f3dce1bda0c4b01f9698e9166f98c84f92640abe3f6317834a42e5c12573b46842c1a6ea8fe6ca9c006dca48a2087e1f983dfb5692771e4a0b15b337ad669b1d08b40862b176bace5331b49a767375b1a8469012aa70a67b55fe71b72478201d0b3ac7269c064c960361e92ee7ba8a42cc6b582bf9b965fb388fa9172ad44c4b073ac23c02080a6bcd106b691ffdf4c7cf71e42f2063fcf196e9bddc5e85be1fe5048eb1b31b460efbb46d76195eef9904c4cba326f2e17ff51fec17dd965aa06dadd4ab07d6966e4a7c38e8afd66dfde56c872bb87516a8f7313c797e4d80e5ad4a5f7afad95c1e0449254adae052e71a3fb98399f93ab30848e0d23252dd45e6fd41bc5fa7303dfb846a8fd713a0032a0b0ae96dfba1bbe41d20abd8099e2cb7fccc329d25bd153029139ef05d090a5093ea557693c0a8d491395b8a23ca844b3887dd5dfc29ac06f4b9be87883a793211b973465e2644c4f5de02b8ab01571401203fc2740423826858cc6da0194c195d27aac4ec4b9d23d506c1501d06440aca3fc180926d75d4a004d3dff21eb4ea1e8c86e6c9627248eff953e1d192d5c8efc006a7e512388ef2ebdb72ee3ad42d719f28e8f994e12ebf4c79f2ffe3abd7408ccd2236a7b89b2606247a732c10c4"
)

def encode_varint(n: int) -> bytes:
    out = bytearray()
    if n < 0: n &= 0xFFFFFFFFFFFFFFFF
    while True:
        b = n & 0x7F; n >>= 7
        if n: b |= 0x80
        out.append(b)
        if not n: break
    return bytes(out)

def _pb_varint(fn, val): return encode_varint((fn<<3)|0) + encode_varint(val)
def _pb_length(fn, val):
    enc = val.encode('utf-8') if isinstance(val,str) else val
    return encode_varint((fn<<3)|2) + encode_varint(len(enc)) + enc

def create_proto(fields) -> bytes:
    packet = bytearray()
    for field, value in fields.items():
        if isinstance(field, str): field = int(field)
        if isinstance(value, dict):
            packet.extend(_pb_length(field, bytes(create_proto(value))))
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict): packet.extend(_pb_length(field, bytes(create_proto(item))))
                elif isinstance(item, str): packet.extend(_pb_length(field, item))
                elif isinstance(item, (bytes, bytearray)): packet.extend(_pb_length(field, bytes(item)))
                elif isinstance(item, bool): packet.extend(_pb_varint(field, 1 if item else 0))
                elif isinstance(item, int): packet.extend(_pb_varint(field, item))
        elif isinstance(value, bool): packet.extend(_pb_varint(field, 1 if value else 0))
        elif isinstance(value, int): packet.extend(_pb_varint(field, value))
        elif isinstance(value, str): packet.extend(_pb_length(field, value))
        elif isinstance(value, (bytes, bytearray)): packet.extend(_pb_length(field, bytes(value)))
    return bytes(packet)

def encrypt_aes(hex_data: str) -> str:
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return cipher.encrypt(pad(bytes.fromhex(hex_data), AES.block_size)).hex()

def decode_varint(data, offset):
    result = 0; shift = 0
    while offset < len(data):
        byte = data[offset]
        result |= (byte & 0x7F) << shift
        offset += 1
        if not (byte & 0x80): return result, offset
        shift += 7
    return None, offset

def decode_protobuf_2(data):
    result = {}; offset = 0; data_len = len(data)
    while offset < data_len:
        header, offset = decode_varint(data, offset)
        if header is None: break
        fn = header >> 3; wt = header & 0x7
        if wt == 0:
            v, offset = decode_varint(data, offset)
            if v is not None: result[fn] = v
        elif wt == 2:
            length, offset = decode_varint(data, offset)
            if length is None: break
            value = data[offset:offset+length]; offset += length
            try: result[fn] = value.decode('utf-8') if value else value.hex()
            except Exception: result[fn] = value.hex()
        elif wt == 1: offset += 8
        elif wt == 3: offset += 4
        else: break
    return result

def extract_raw_fields(data: bytes) -> dict:
    result = {}; offset = 0; data_len = len(data)
    while offset < data_len:
        header, offset = decode_varint(data, offset)
        if header is None: break
        fn = header >> 3; wt = header & 0x7
        if wt == 0:
            v, offset = decode_varint(data, offset)
            if v is not None: result[fn] = v
        elif wt == 2:
            length, offset = decode_varint(data, offset)
            if length is None: break
            if offset + length > data_len: break
            result[fn] = bytes(data[offset:offset+length]); offset += length
        elif wt == 1: offset += 8
        elif wt == 3: offset += 4
        else: break
    return result

def _parse_results_sync(results):
    out = {}
    for r in results:
        fd = {"wire_type": r.wire_type}
        if r.wire_type == "varint": fd["data"] = r.data
        elif r.wire_type in ("string","bytes"): fd["data"] = r.data
        elif r.wire_type == "length_delimited":
            if hasattr(r.data, "results"): fd["data"] = _parse_results_sync(r.data.results)
            elif isinstance(r.data, list): fd["data"] = _parse_results_sync(r.data)
            else: fd["data"] = str(r.data)
        out[str(r.field)] = fd
    return out

def decode_protobuf_dict(data: bytes) -> dict:
    try: return _parse_results_sync(Parser().parse(data))
    except Exception: return {}

def _extract_key_iv(res_json):
    if "__RAW_HEX__" in res_json and "__OFFSET__" in res_json:
        try:
            raw = bytes.fromhex(res_json["__RAW_HEX__"])
            off = int(res_json["__OFFSET__"])
            rf = extract_raw_fields(raw[off:])
            for kf, vf in [(22,23),(24,25),(6,7)]:
                k = rf.get(kf); v = rf.get(vf)
                if isinstance(k,(bytes,bytearray)) and len(k)==16 and isinstance(v,(bytes,bytearray)) and len(v)==16:
                    return bytes(k), bytes(v)
        except Exception: pass
    found = {}
    for k, v in res_json.items():
        if str(k).startswith("__"): continue
        if not isinstance(v, dict): continue
        data = v.get("data")
        if data is None: continue
        raw = None
        if isinstance(data, (bytes,bytearray)) and len(data)==16: raw = bytes(data)
        elif isinstance(data, str) and len(data)==32:
            try:
                c = bytes.fromhex(data)
                if len(c)==16: raw = c
            except Exception: pass
        if raw and len(raw)==16:
            try: found[int(k)] = raw
            except Exception: pass
    if len(found) < 2: return None, None
    for kf, vf in [(22,23),(24,25),(6,7)]:
        if kf in found and vf in found: return found[kf], found[vf]
    sk = sorted(found.keys())
    return found[sk[0]], found[sk[1]]

def get_app_version():
    try: return play_scraper('com.dts.freefireth').get('version')
    except Exception: return "1.132.9"

async def version_config(region="IND"):
    app_version = get_app_version()
    lang = REGION_LANG.get(region.upper(), "en")
    url = (f"https://version.ggwhitehawk.com/live/ver.php?version={app_version}"
           f"&lang={lang}&device=android&channel=android&appstore=googleplay"
           f"&region={region.upper()}&whitelist_version=1.3.0&whitelist_sp_version=1.0.0")
    fallback_release, fallback_server, fallback_gop = "1.132.9", "https://clientbp.ggbluehawk.com", "https://ffmconnect.ppmainecoonghj.com"
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get(url, timeout=10) as r:
                if 'application/json' not in r.headers.get('Content-Type', ''):
                    return fallback_release, app_version, fallback_server, fallback_gop, app_version
                j = await r.json()
                return j.get("latest_release_version", fallback_release), j.get("remote_version", app_version), j.get("server_url", fallback_server), (j.get("gop_url","").split(";")[0].strip() or fallback_gop), app_version
    except Exception:
        return fallback_release, app_version, fallback_server, fallback_gop, app_version

def generate_signature(payload_str):
    return hmac.new(API_KEY, payload_str.encode(), hashlib.sha256).hexdigest()

async def register_account(password, gop_url, app_version):
    rp = {"app_id":100067,"client_type":2,"password":password,"source":2}
    payload = json.dumps(rp, separators=(',',':'))
    sig = generate_signature(payload)
    headers = {"User-Agent": f"GarenaMSDK/4.0.44(SM-E135F ;Android 14;en;GB;app {app_version} 2019118525;)", "Authorization": f"Signature {sig}", "Accept": "application/json", "Content-Type": "application/json; charset=utf-8"}
    try:
        async with aiohttp.ClientSession() as s:
            async with s.post(f"{gop_url}/api/v2/oauth/guest:register", headers=headers, data=payload, timeout=10) as resp:
                data = json.loads(await resp.text())
                if data.get("code") == 0: return data["data"]["uid"]
    except Exception: pass
    return None

async def grant_token(uid, password, gop_url, app_version):
    gp = {"client_id":100067,"client_secret":HEX_KEY,"client_type":2,"device_id":f"02-{uuid.uuid4()}","password":password,"response_type":"token","uid":int(uid)}
    payload = json.dumps(gp, separators=(',',':'))
    sig = generate_signature(payload)
    headers = {"User-Agent": f"GarenaMSDK/4.0.44(SM-E135F ;Android 14;en;GB;app {app_version} 2019118525;)", "Authorization": f"Signature {sig}", "Accept": "application/json", "Content-Type": "application/json; charset=utf-8"}
    try:
        async with aiohttp.ClientSession() as s:
            async with s.post(f"{gop_url}/api/v2/oauth/guest/token:grant", headers=headers, data=payload, timeout=10) as resp:
                data = json.loads(await resp.text())
                if data.get("code") == 0: return data["data"]
    except Exception: pass
    return None

async def get_payload(access_token, open_id, platform, version, lang_code="hi"):
    device_id = f"Google|{uuid.uuid4()}"
    major_login = {
        "3": str(time.strftime("%Y-%m-%d %H:%M:%S")), "4": "free fire", "5": 1, "7": f"{version}",
        "8": "Android OS 14 / API-34", "9": "Handheld", "11": "CarrierDataNetwork", "12": 1672, "13": 750, "14": "338",
        "15": "ARMv7 VFPv3 NEON", "16": 3702, "17": "Mali-G52", "18": "OpenGL ES 3.2", "19": device_id,
        "20": "104.28.197.151", "21": lang_code, "22": f"{open_id}", "23": f"{platform}", "24": "Handheld",
        "25": "samsung SM-E135F", "26": "IND", "29": f"{access_token}", "30": 1, "42": "Cellular",
        "57": "7428b253defc164018c604a1ebbfebdf", "60": 52037, "61": 5355, "62": 3723, "63": 3,
        "64": 5483, "65": 52037, "66": 5483, "67": 52037, "73": 2, "76": 1, "78": 3, "79": 1,
        "81": "32", "83": "2019121229", "86": "OpenGLES2", "87": 8191, "88": int(platform),
        "92": 16091, "93": "android", "95": 111107, "97": 1, "98": 1, "99": f"{platform}",
        "100": f"{platform}", "102": "4503454457550c0766", "104": 53792, "105": 1,
    }
    get_login_data = dict(major_login)
    get_login_data["99"] = "0"
    get_login_data["103"] = 1
    return bytes.fromhex(encrypt_aes(create_proto(major_login).hex())), bytes.fromhex(encrypt_aes(create_proto(get_login_data).hex()))

async def major_register(release_v, access_token, open_id, name, game_version, login_url, lang_code="hi"):
    field14 = bytes(ord(c) ^ KEYSTREAM[i % 32] for i, c in enumerate(open_id))
    fields = {1: name, 2: access_token, 3: open_id, 5: 102000007, 6: 4, 7: 1, 13: 1, 14: field14, 15: lang_code, 16: 2, 20: game_version, 21: 1, 22: GGRE_RAW}
    payload = AES.new(AES_KEY, AES.MODE_CBC, AES_IV).encrypt(pad(create_proto(fields), 16))
    hdrs = {"Accept": "*/*", "Authorization": "Bearer ", "Content-Type": "application/x-www-form-urlencoded", "ReleaseVersion": f"{release_v}", "User-Agent": "UnityPlayer/2018.4.12f1"}
    try:
        ssl_ctx = ssl.create_default_context(); ssl_ctx.check_hostname = False; ssl_ctx.verify_mode = ssl.CERT_NONE
        async with aiohttp.ClientSession() as s:
            async with s.post(f"{login_url.rstrip('/')}/MajorRegister", headers=hdrs, data=payload, ssl=ssl_ctx, timeout=10) as resp:
                content = await resp.read()
                if resp.status != 200 or not content: return None
                for off in [0, 64, 48, 32, 16]:
                    if off >= len(content): continue
                    try:
                        r = decode_protobuf_2(content[off:])
                        if r and 3 in r: return {str(k): {"data": v} for k, v in r.items()}
                    except Exception: pass
                return None
    except Exception: return None

async def major_login(payload, login_url, release_version):
    hdrs = {"Accept": "*/*", "Authorization": "Bearer ", "Content-Type": "application/x-www-form-urlencoded", "ReleaseVersion": f"{release_version}", "User-Agent": "UnityPlayer/2018.4.12f1"}
    try:
        ssl_ctx = ssl.create_default_context(); ssl_ctx.check_hostname = False; ssl_ctx.verify_mode = ssl.CERT_NONE
        async with aiohttp.ClientSession() as s:
            async with s.post(f"{login_url.rstrip('/')}/MajorLogin", headers=hdrs, data=payload, ssl=ssl_ctx, timeout=10) as resp:
                content = await resp.read()
                if resp.status != 200 or len(content) < 200: return None
                for offset in [64, 0, 48, 32, 80, 16, 128, 8]:
                    if offset >= len(content): continue
                    try:
                        cand = decode_protobuf_dict(content[offset:])
                        if cand and (("8" in cand) or (8 in cand)):
                            cand["__RAW_HEX__"] = content.hex(); cand["__OFFSET__"] = offset
                            return cand
                    except Exception: pass
                return None
    except Exception: return None

async def get_login_data(payload, jwt_token, server_url, release_version):
    hdrs = {"Accept": "*/*", "Authorization": f"Bearer {jwt_token}", "Content-Type": "application/x-www-form-urlencoded", "ReleaseVersion": f"{release_version}", "User-Agent": "UnityPlayer/2018.4.12f1"}
    try:
        ssl_ctx = ssl.create_default_context(); ssl_ctx.check_hostname = False; ssl_ctx.verify_mode = ssl.CERT_NONE
        async with aiohttp.ClientSession() as s:
            async with s.post(f"{server_url.rstrip('/')}/GetLoginData", headers=hdrs, data=payload, ssl=ssl_ctx, timeout=10) as r:
                if r.status != 200: return None
                content = await r.read()
                for off in [0, 64, 48, 32, 80, 16]:
                    if off >= len(content): continue
                    try:
                        c = decode_protobuf_dict(content[off:])
                        if c and len(c) >= 3: return c
                    except Exception: pass
        return None
    except Exception: return None

async def generate_single_account(region="IND", password="Spyro"):
    vc = await version_config(region)
    if not vc: return None
    release_v, remote_v, login_url, gop_1, app_version = vc
    lang = REGION_LANG.get(region.upper(), "hi")
    game_version = remote_v or app_version

    uid = await register_account(password, gop_1, app_version)
    if not uid: return None

    tok_data = await grant_token(uid, password, gop_1, app_version)
    if not tok_data: return None

    open_id, access_token, platform = tok_data["open_id"], tok_data["access_token"], tok_data.get("platform", 4)
    major_payload, login_payload = await get_payload(access_token, open_id, platform, game_version, lang)
    
    nickname = f"Spyro{''.join(random.choices(string.ascii_uppercase + string.digits, k=4))}"
    mr = await major_register(release_v, access_token, open_id, nickname, game_version, login_url, lang)
    if not mr: return None

    await asyncio.sleep(2.0)
    res_json = await major_login(major_payload, login_url, release_v)
    if not res_json: return None

    def _gd(k):
        v = res_json.get(str(k))
        if isinstance(v, dict) and "data" in v: return v["data"]
        if k in res_json and not isinstance(res_json[k], dict): return res_json[k]
        return v.get("data") if isinstance(v, dict) else None

    jwt_token, server_url_raw, acc_id_raw = _gd(8), _gd(10), _gd(1)
    aes_ak, iv_i = _extract_key_iv(res_json)
    if not jwt_token or not server_url_raw: return None

    ld = await get_login_data(login_payload, jwt_token, server_url_raw, release_v)
    def _gf(f, d=None):
        if not ld: return d
        v = ld.get(str(f), {}).get("data")
        return v if v is not None else d

    return {
        'auth_uid': uid,
        'auth_password': password,
        'account_id': acc_id_raw,
        'nickname': nickname,
        'region': region,
        'level': int(_gf(6, 1) or 1),
        'token': jwt_token,
        'server_url': server_url_raw
    }
