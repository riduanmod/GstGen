import hmac
import hashlib
import requests
import string
import random
import json
import codecs
import time
import base64
import logging
import urllib3
from datetime import datetime
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# Disable SSL Warnings for speed
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- APP CONFIGURATION ---
app = FastAPI(
    title="Premium Account Generator API",
    description="Generates and fully activates a Free Fire guest account.",
    version="2.0.0"
)

# Constants & Keys
HEX_KEY = "32656534343831396539623435393838343531343130363762323831363231383734643064356437616639643866376530306331653534373135623764316533"
KEY_BYTES = bytes.fromhex(HEX_KEY)

# Region mapping
REGIONS_CONFIG = {
    'IND': {'lang': 'hi', 'client_host': 'client.ind.freefiremobile.com', 'login_host': 'loginbp.common.ggbluefox.com'},
    'BD':  {'lang': 'bn', 'client_host': 'clientbp.ggblueshark.com',      'login_host': 'loginbp.ggblueshark.com'},
    'PK':  {'lang': 'ur', 'client_host': 'clientbp.ggblueshark.com',      'login_host': 'loginbp.ggblueshark.com'},
    'ID':  {'lang': 'id', 'client_host': 'clientbp.ggblueshark.com',      'login_host': 'loginbp.ggblueshark.com'},
    'TH':  {'lang': 'th', 'client_host': 'clientbp.common.ggbluefox.com', 'login_host': 'loginbp.common.ggbluefox.com'},
    'VN':  {'lang': 'vi', 'client_host': 'clientbp.ggblueshark.com',      'login_host': 'loginbp.ggblueshark.com'},
    'BR':  {'lang': 'pt', 'client_host': 'clientbp.ggblueshark.com',      'login_host': 'loginbp.ggblueshark.com'},
    'ME':  {'lang': 'ar', 'client_host': 'clientbp.ggblueshark.com',      'login_host': 'loginbp.common.ggbluefox.com'},
    'CIS': {'lang': 'ru', 'client_host': 'clientbp.ggblueshark.com',      'login_host': 'loginbp.ggblueshark.com'},
    'SG':  {'lang': 'en', 'client_host': 'clientbp.ggblueshark.com',      'login_host': 'loginbp.ggblueshark.com'}
}

# --- RESPONSE MODEL ---
class AccountResponse(BaseModel):
    status: str
    message: str
    is_active: bool
    server_region: str
    account_name: str
    uid: str
    account_id: str
    password: str
    jwt_token: str

# --- CORE CRYPTO & LOGIC ---
def generate_custom_password() -> str:
    characters = string.ascii_letters + string.digits
    random_part = ''.join(random.choice(characters) for _ in range(5))
    return f"Riduan_{random_part}"

def generate_random_name(base_name: str) -> str:
    exponent_digits = {'0': '⁰', '1': '¹', '2': '²', '3': '³', '4': '⁴', '5': '⁵', '6': '⁶', '7': '⁷', '8': '⁸', '9': '⁹'}
    number = random.randint(1, 99999)
    exponent_str = ''.join(exponent_digits[digit] for digit in f"{number:05d}")
    return f"{base_name[:7]}{exponent_str}"

def encrypt_api(plain_text: str) -> str:
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(bytes.fromhex(plain_text), AES.block_size)).hex()

def encode_string(original: str) -> dict:
    keystream = [0x30, 0x30, 0x30, 0x32, 0x30, 0x31, 0x37, 0x30, 0x30, 0x30, 0x30, 0x30, 0x32, 0x30, 0x31, 0x37,
                 0x30, 0x30, 0x30, 0x30, 0x30, 0x32, 0x30, 0x31, 0x37, 0x30, 0x30, 0x30, 0x30, 0x30, 0x32, 0x30]
    encoded = "".join(chr(ord(original[i]) ^ keystream[i % len(keystream)]) for i in range(len(original)))
    return {"open_id": original, "field_14": encoded}

def to_unicode_escaped(s: str) -> str:
    return ''.join(c if 32 <= ord(c) <= 126 else f'\\u{ord(c):04x}' for c in s)

def EnC_Vr(N: int) -> bytes:
    if N < 0: return b''
    H = []
    while True:
        BesTo = N & 0x7F; N >>= 7
        if N: BesTo |= 0x80
        H.append(BesTo)
        if not N: break
    return bytes(H)

def CrEaTe_VarianT(field_number: int, value: int) -> bytes: 
    return EnC_Vr((field_number << 3) | 0) + EnC_Vr(value)

def CrEaTe_LenGTh(field_number: int, value: bytes | str) -> bytes:
    encoded_value = value.encode() if isinstance(value, str) else value
    return EnC_Vr((field_number << 3) | 2) + EnC_Vr(len(encoded_value)) + encoded_value

def CrEaTe_ProTo(fields: dict) -> bytes:
    packet = bytearray()    
    for field, value in fields.items():
        if isinstance(value, dict): packet.extend(CrEaTe_LenGTh(field, CrEaTe_ProTo(value)))
        elif isinstance(value, int): packet.extend(CrEaTe_VarianT(field, value))           
        elif isinstance(value, str) or isinstance(value, bytes): packet.extend(CrEaTe_LenGTh(field, value))           
    return bytes(packet)

def build_activation_payload(jwt_token: str, access_token: str) -> bytes:
    try:
        token_payload_base64 = jwt_token.split('.')[1]
        token_payload_base64 += '=' * ((4 - len(token_payload_base64) % 4) % 4)
        decoded_payload = json.loads(base64.urlsafe_b64decode(token_payload_base64).decode('utf-8'))
        
        external_id = decoded_payload['external_id']
        signature_md5 = decoded_payload['signature_md5']
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        payload = bytes.fromhex("1a13323032352d30372d33302031313a30323a3531220966726565206669726528013a07312e3132302e32422c416e64726f6964204f5320372e312e32202f204150492d323320284e32473438482f373030323530323234294a0848616e6468656c645207416e64726f69645a045749464960c00c68840772033332307a1f41524d7637205646507633204e454f4e20564d48207c2032343635207c203480019a1b8a010f416472656e6f2028544d292036343092010d4f70656e474c20455320332e319a012b476f6f676c657c31663361643662372d636562342d343934622d383730622d623164616364373230393131a2010c3139372e312e31322e313335aa0102656eb201203939366136323964626364623339363462653662363937386635643831346462ba010134c2010848616e6468656c64ea014066663930633037656239383135616633306134336234613966363031393531366530653463373033623434303932353136643064656661346365663531663261f00101ca0207416e64726f6964d2020457494649ca03203734323862323533646566633136343031386336303461316562626665626466e003daa907e803899b07f003bf0ff803ae088004999b078804daa9079004999b079804daa907c80403d204262f646174612f6170702f636f6d2e6474732e667265656669726574682d312f6c69622f61726de00401ea044832303837663631633139663537663261663465376665666630623234643964397c2f646174612f6170702f636f6d2e6474732e667265656669726574682d312f626173652e61706bf00403f804018a050233329a050a32303139313138363933b205094f70656e474c455332b805ff7fc00504e005dac901ea0507616e64726f6964f2055c4b71734854394748625876574c6668437950416c52526873626d43676542557562555551317375746d525536634e30524f3751453141486e496474385963784d614c575437636d4851322b7374745279377830663935542b6456593d8806019006019a060134a2060134")
        
        payload = payload.replace(b"2025-07-30 11:02:51", now.encode())
        payload = payload.replace(b"ff90c07eb9815af30a43b4a9f6019516e0e4c703b44092516d0defa4cef51f2a", access_token.encode("UTF-8"))
        payload = payload.replace(b"996a629dbcdb3964be6b6978f5d814db", external_id.encode("UTF-8"))
        payload = payload.replace(b"7428b253defc164018c604a1ebbfebdf", signature_md5.encode("UTF-8"))
        
        encrypted = encrypt_api(payload.hex())
        return bytes.fromhex(encrypted) if encrypted else None
    except Exception as e:
        return None

# --- API ENDPOINTS ---
@app.get("/acc_gen", response_model=AccountResponse)
def generate_and_activate_account(
    name: str = Query(..., description="Desired account name"),
    region: str = Query(..., description="Server region (e.g., BD, IND, SG)")
):
    region_code = region.upper()
    if region_code not in REGIONS_CONFIG:
        config = {'lang': 'en', 'client_host': 'clientbp.ggblueshark.com', 'login_host': 'loginbp.ggblueshark.com'}
    else:
        config = REGIONS_CONFIG[region_code]
    
    final_account_name = generate_random_name(name.replace(" ", "　"))
    password = generate_custom_password()

    # Vercel-এর জন্য Session ব্যবহার করা হচ্ছে যাতে স্পিড বাড়ে
    req_session = requests.Session()
    req_session.headers.update({"Accept-Encoding": "gzip", "Connection": "Keep-Alive"})

    try:
        # --- 1. GUEST REGISTER ---
        data = f"password={password}&client_type=2&source=2&app_id=100067"
        sig = hmac.new(KEY_BYTES, data.encode('utf-8'), hashlib.sha256).hexdigest()
        reg_headers = {
            "User-Agent": "GarenaMSDK/4.0.19P8(ASUS_Z01QD ;Android 12;en;US;)",
            "Authorization": "Signature " + sig,
            "Content-Type": "application/x-www-form-urlencoded"
        }
        res_reg = req_session.post("https://100067.connect.garena.com/oauth/guest/register", headers=reg_headers, data=data, verify=False, timeout=6)
        if 'uid' not in res_reg.json(): 
            raise ValueError("Guest Register Failed")
        uid = res_reg.json()['uid']
        
        # --- 2. GET GUEST TOKEN ---
        body = {
            "uid": uid, "password": password, "response_type": "token",
            "client_type": "2", "client_secret": KEY_BYTES, "client_id": "100067"
        }
        res_tok = req_session.post("https://100067.connect.garena.com/oauth/guest/token/grant", headers=reg_headers, data=body, verify=False, timeout=6)
        tok_data = res_tok.json()
        if 'open_id' not in tok_data: 
            raise ValueError("Guest Token Failed")
        
        open_id = tok_data['open_id']
        access_token = tok_data["access_token"]
        
        result = encode_string(open_id)
        field = codecs.decode(to_unicode_escaped(result['field_14']), 'unicode_escape').encode('latin1')
        
        # --- 3. MAJOR REGISTER ---
        major_url = f"https://{config['login_host']}/MajorRegister"
        payload_mr = {
            1: final_account_name, 2: access_token, 3: open_id, 5: 102000007,
            6: 4, 7: 1, 13: 1, 14: field, 15: config['lang'], 16: 1, 17: 1
        }
        enc_payload_mr = bytes.fromhex(encrypt_api(CrEaTe_ProTo(payload_mr).hex()))
        headers_major = {
            "Authorization": "Bearer", "Content-Type": "application/x-www-form-urlencoded",
            "Host": config['login_host'], "ReleaseVersion": "OB52",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_I005DA Build/PI)",
            "X-GA": "v1 1", "X-Unity-Version": "2018.4.11f1"
        }
        res_major_reg = req_session.post(major_url, headers=headers_major, data=enc_payload_mr, verify=False, timeout=6)
        if res_major_reg.status_code != 200:
            raise ValueError("Major Register Failed")
        
        # --- 4. MAJOR LOGIN ---
        ml_payload_parts = [
            b'\x1a\x132025-08-30 05:19:21"\tfree fire(\x01:\x081.114.13B2Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)J\x08HandheldR\nATM MobilsZ\x04WIFI`\xb6\nh\xee\x05r\x03300z\x1fARMv7 VFPv3 NEON VMH | 2400 | 2\x80\x01\xc9\x0f\x8a\x01\x0fAdreno (TM) 640\x92\x01\rOpenGL ES 3.2\x9a\x01+Google|dfa4ab4b-9dc4-454e-8065-e70c733fa53f\xa2\x01\x0e105.235.139.91\xaa\x01\x02',
            config['lang'].encode("ascii"),
            b'\xb2\x01 1d8ec0240ede109973f3321b9354b44d\xba\x01\x014\xc2\x01\x08Handheld\xca\x01\x10Asus ASUS_I005DA\xea\x01@afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390\xf0\x01\x01\xca\x02\nATM Mobils\xd2\x02\x04WIFI\xca\x03 7428b253defc164018c604a1ebbfebdf\xe0\x03\xa8\x81\x02\xe8\x03\xf6\xe5\x01\xf0\x03\xaf\x13\xf8\x03\x84\x07\x80\x04\xe7\xf0\x01\x88\x04\xa8\x81\x02\x90\x04\xe7\xf0\x01\x98\x04\xa8\x81\x02\xc8\x04\x01\xd2\x04=/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/lib/arm\xe0\x04\x01\xea\x04_2087f61c19f57f2af4e7feff0b24d9d9|/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/base.apk\xf0\x04\x03\xf8\x04\x01\x8a\x05\x0232\x9a\x05\n2019118692\xb2\x05\tOpenGLES2\xb8\x05\xff\x7f\xc0\x05\x04\xe0\x05\xf3F\xea\x05\x07android\xf2\x05pKqsHT5ZLWrYljNb5Vqh//yFRlaPHSO9NWSQsVvOmdhEEn7W+VHNUK+Q+fduA3ptNrGB0Ll0LRz3WW0jOwesLj6aiU7sZ40p8BfUE/FI/jzSTwRe2\xf8\x05\xfb\xe4\x06\x88\x06\x01\x90\x06\x01\x9a\x06\x014\xa2\x06\x014\xb2\x06"GQ@O\x00\x0e^\x00D\x06UA\x0ePM\r\x13hZ\x07T\x06\x0cm\\V\x0ejYV;\x0bU5'
        ]
        ml_data = b''.join(ml_payload_parts)
        ml_data = ml_data.replace(b'afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390', access_token.encode())
        ml_data = ml_data.replace(b'1d8ec0240ede109973f3321b9354b44d', open_id.encode())
        
        enc_ml_data = bytes.fromhex(encrypt_api(ml_data.hex()))
        res_ml = req_session.post(f"https://{config['login_host']}/MajorLogin", headers=headers_major, data=enc_ml_data, verify=False, timeout=6)
        
        if res_ml.status_code != 200: 
            raise ValueError("Major Login Failed")
        
        # Fast JWT Extraction (Protobuf ছাড়া)
        jwt_token = None
        if len(res_ml.text) > 10:
            jwt_start = res_ml.text.find("eyJ")
            if jwt_start != -1:
                jwt_token_raw = res_ml.text[jwt_start:]
                second_dot = jwt_token_raw.find(".", jwt_token_raw.find(".") + 1)
                if second_dot != -1: jwt_token = jwt_token_raw[:second_dot + 44]
        
        if not jwt_token: 
            raise ValueError("JWT Token Extraction Failed")

        account_id = "N/A"
        try:
            payload_part = jwt_token.split('.')[1]
            payload_part += '=' * ((4 - len(payload_part) % 4) % 4)
            jwt_data = json.loads(base64.urlsafe_b64decode(payload_part).decode('utf-8'))
            account_id = str(jwt_data.get('account_id', jwt_data.get('external_id', "N/A")))
        except: pass

        # --- 5. FORCE REGION BINDING ---
        if region_code != "BR":
            reg_bind = "RU" if region_code == "CIS" else region_code
            enc_region = encrypt_api(CrEaTe_ProTo({1: reg_bind}).hex())
            headers_choose = headers_major.copy()
            headers_choose["Authorization"] = f"Bearer {jwt_token}"
            req_session.post(f"https://{config['login_host']}/ChooseRegion", headers=headers_choose, data=bytes.fromhex(enc_region), verify=False, timeout=5)

        # --- 6. GET LOGIN DATA (FINAL ACTIVATION) ---
        activation_payload = build_activation_payload(jwt_token, access_token)
        if not activation_payload: 
            raise ValueError("Activation Payload Creation Failed")

        headers_act = {
            'Authorization': f'Bearer {jwt_token}', 'X-Unity-Version': '2018.4.11f1',
            'X-GA': 'v1 1', 'ReleaseVersion': 'OB52', 'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; G011A Build/PI)',
            'Host': config['client_host']
        }
        
        res_act = req_session.post(f"https://{config['client_host']}/GetLoginData", headers=headers_act, data=activation_payload, verify=False, timeout=6)
        
        if res_act.status_code == 200:
            return AccountResponse(
                status="success",
                message="Account successfully generated and activated in OB52.",
                is_active=True,
                server_region=region_code,
                account_name=final_account_name,
                uid=uid,
                account_id=account_id,
                password=password,
                jwt_token=jwt_token
            )
        else:
            raise ValueError(f"Activation Failed with status {res_act.status_code}")

    except Exception as e:
        logging.error(f"Execution Error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Process Failed: {str(e)}")
