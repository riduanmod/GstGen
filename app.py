import hmac
import hashlib
import requests
import string
import random
import json
import codecs
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

# --- PROTOBUF INTEGRATION (Fallback Support) ---
try:
    from MajorLoginRes_pb2 import MajorLoginRes
    PROTOBUF_AVAILABLE = True
except ImportError:
    PROTOBUF_AVAILABLE = False
    logging.warning("MajorLoginRes_pb2 not found. Falling back to string slicing for JWT extraction.")

# --- APP CONFIGURATION ---
app = FastAPI(
    title="Premium Account Generator API",
    description="Generates a Free Fire guest account based on OB52 Fixed Logic.",
    version="2.0.0"
)

# Constants & Keys
HEX_KEY = "32656534343831396539623435393838343531343130363762323831363231383734643064356437616639643866376530306331653534373135623764316533"
KEY_BYTES = bytes.fromhex(HEX_KEY)

REGION_LANG = {
    "ME": "ar", "IND": "hi", "ID": "id", "VN": "vi", "TH": "th", 
    "BD": "bn", "PK": "ur", "TW": "zh", "CIS": "ru", "SAC": "es", "BR": "pt"
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

# --- CORE CRYPTO & HELPER LOGIC ---
def generate_custom_password(prefix="Riduan") -> str:
    SECRET_KEY = "RiduanOfficialBD"
    characters = string.ascii_uppercase + string.digits
    part1 = ''.join(random.choice(characters) for _ in range(5))
    part2 = ''.join(random.choice(characters) for _ in range(5))
    return f"{prefix}_{part1}_{SECRET_KEY}_{part2}"

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

def E_AEs(Pc: str) -> bytes:
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    return AES.new(key, AES.MODE_CBC, iv).encrypt(pad(bytes.fromhex(Pc), AES.block_size))

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

def decode_jwt_token(jwt_token: str) -> str:
    try:
        parts = jwt_token.split('.')
        if len(parts) >= 2:
            payload_part = parts[1]
            padding = 4 - len(payload_part) % 4
            if padding != 4: payload_part += '=' * padding
            decoded = base64.urlsafe_b64decode(payload_part)
            data = json.loads(decoded)
            account_id = data.get('account_id') or data.get('external_id')
            if account_id: return str(account_id)
    except: pass
    return "N/A"

# --- API ENDPOINTS ---
@app.get("/acc_gen", response_model=AccountResponse)
def generate_account(
    name: str = Query(..., description="Desired account base name"),
    region: str = Query(..., description="Server region (e.g., BD, IND, SG)")
):
    region_code = region.upper()
    lang_code = REGION_LANG.get(region_code, "en")
    
    url_host = "loginbp.common.ggbluefox.com" if region_code in ["ME", "TH"] else "loginbp.ggblueshark.com"

    final_account_name = generate_random_name(name.replace(" ", "　"))
    password = generate_custom_password("Riduan")

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
        res_reg = req_session.post("https://100067.connect.garena.com/oauth/guest/register", headers=reg_headers, data=data, verify=False, timeout=10)
        res_reg.raise_for_status()
        
        res_reg_json = res_reg.json()
        if 'uid' not in res_reg_json: 
            raise ValueError("Guest Register Failed: No UID returned")
        
        # FIX: Force UID to be a string
        uid = str(res_reg_json['uid'])
        
        # --- 2. GET GUEST TOKEN ---
        body = {
            "uid": uid, "password": password, "response_type": "token",
            "client_type": "2", "client_secret": KEY_BYTES, "client_id": "100067"
        }
        res_tok = req_session.post("https://100067.connect.garena.com/oauth/guest/token/grant", headers=reg_headers, data=body, verify=False, timeout=10)
        res_tok.raise_for_status()
        
        tok_data = res_tok.json()
        if 'open_id' not in tok_data: 
            raise ValueError("Guest Token Failed: No open_id returned")
        
        open_id = tok_data['open_id']
        access_token = tok_data["access_token"]
        
        result = encode_string(open_id)
        field = codecs.decode(to_unicode_escaped(result['field_14']), 'unicode_escape').encode('latin1')
        
        # --- 3. MAJOR REGISTER ---
        major_url = f"https://{url_host}/MajorRegister"
        payload_mr = {
            1: final_account_name, 2: access_token, 3: open_id, 5: 102000007,
            6: 4, 7: 1, 13: 1, 14: field, 15: lang_code, 16: 1, 17: 1
        }
        enc_payload_mr = E_AEs(CrEaTe_ProTo(payload_mr).hex())
        
        headers_major = {
            "Authorization": "Bearer", "Content-Type": "application/x-www-form-urlencoded",
            "Expect": "100-continue", "Host": url_host, "ReleaseVersion": "OB52",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_I005DA Build/PI)",
            "X-GA": "v1 1", "X-Unity-Version": "2018.4.11f1"
        }
        
        res_major_reg = req_session.post(major_url, headers=headers_major, data=enc_payload_mr, verify=False, timeout=15)
        if res_major_reg.status_code != 200:
            raise ValueError(f"Major Register Failed with status {res_major_reg.status_code}")
        
        # --- 4. MAJOR LOGIN ---
        ml_payload_parts = [
            b'\x1a\x132025-08-30 05:19:21"\tfree fire(\x01:\x081.114.13B2Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)J\x08HandheldR\nATM MobilsZ\x04WIFI`\xb6\nh\xee\x05r\x03300z\x1fARMv7 VFPv3 NEON VMH | 2400 | 2\x80\x01\xc9\x0f\x8a\x01\x0fAdreno (TM) 640\x92\x01\rOpenGL ES 3.2\x9a\x01+Google|dfa4ab4b-9dc4-454e-8065-e70c733fa53f\xa2\x01\x0e105.235.139.91\xaa\x01\x02',
            lang_code.encode("ascii"),
            b'\xb2\x01 1d8ec0240ede109973f3321b9354b44d\xba\x01\x014\xc2\x01\x08Handheld\xca\x01\x10Asus ASUS_I005DA\xea\x01@afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390\xf0\x01\x01\xca\x02\nATM Mobils\xd2\x02\x04WIFI\xca\x03 7428b253defc164018c604a1ebbfebdf\xe0\x03\xa8\x81\x02\xe8\x03\xf6\xe5\x01\xf0\x03\xaf\x13\xf8\x03\x84\x07\x80\x04\xe7\xf0\x01\x88\x04\xa8\x81\x02\x90\x04\xe7\xf0\x01\x98\x04\xa8\x81\x02\xc8\x04\x01\xd2\x04=/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/lib/arm\xe0\x04\x01\xea\x04_2087f61c19f57f2af4e7feff0b24d9d9|/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/base.apk\xf0\x04\x03\xf8\x04\x01\x8a\x05\x0232\x9a\x05\n2019118692\xb2\x05\tOpenGLES2\xb8\x05\xff\x7f\xc0\x05\x04\xe0\x05\xf3F\xea\x05\x07android\xf2\x05pKqsHT5ZLWrYljNb5Vqh//yFRlaPHSO9NWSQsVvOmdhEEn7W+VHNUK+Q+fduA3ptNrGB0Ll0LRz3WW0jOwesLj6aiU7sZ40p8BfUE/FI/jzSTwRe2\xf8\x05\xfb\xe4\x06\x88\x06\x01\x90\x06\x01\x9a\x06\x014\xa2\x06\x014\xb2\x06"GQ@O\x00\x0e^\x00D\x06UA\x0ePM\r\x13hZ\x07T\x06\x0cm\\V\x0ejYV;\x0bU5'
        ]
        ml_data = b''.join(ml_payload_parts)
        ml_data = ml_data.replace(b'afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390', access_token.encode())
        ml_data = ml_data.replace(b'1d8ec0240ede109973f3321b9354b44d', open_id.encode())
        
        enc_ml_data = bytes.fromhex(encrypt_api(ml_data.hex()))
        res_ml = req_session.post(f"https://{url_host}/MajorLogin", headers=headers_major, data=enc_ml_data, verify=False, timeout=15)
        
        jwt_token = ""
        account_id = "N/A"

        if res_ml.status_code == 200 and len(res_ml.content) > 0:
            if PROTOBUF_AVAILABLE:
                try:
                    major_res = MajorLoginRes()
                    major_res.ParseFromString(res_ml.content)
                    if major_res.token:
                        jwt_token = major_res.token
                        account_id = str(decode_jwt_token(jwt_token)) # Force String
                except Exception as e:
                    logging.error(f"Protobuf parsing failed: {e}")
            
            if not jwt_token and len(res_ml.text) > 10:
                jwt_start = res_ml.text.find("eyJ")
                if jwt_start != -1:
                    jwt_token_raw = res_ml.text[jwt_start:]
                    second_dot = jwt_token_raw.find(".", jwt_token_raw.find(".") + 1)
                    if second_dot != -1: 
                        jwt_token = jwt_token_raw[:second_dot + 44]
                        account_id = str(decode_jwt_token(jwt_token)) # Force String

        if not jwt_token or account_id == "N/A": 
            raise ValueError("Major Login completed, but failed to extract JWT token or Account ID")

        # --- 5. FORCE REGION BINDING ---
        if region_code != "BR":
            reg_bind = "RU" if region_code == "CIS" else region_code
            enc_region = encrypt_api(CrEaTe_ProTo({1: reg_bind}).hex())
            headers_choose = headers_major.copy()
            headers_choose["Authorization"] = f"Bearer {jwt_token}"
            req_session.post(f"https://{url_host}/ChooseRegion", headers=headers_choose, data=bytes.fromhex(enc_region), verify=False, timeout=10)

        # Return Success JSON
        return AccountResponse(
            status="success",
            message="Account generated successfully using OB52 logic.",
            is_active=True,
            server_region=region_code,
            account_name=final_account_name,
            uid=uid, # Now perfectly converted to String
            account_id=account_id, # Safely converted to String
            password=password,
            jwt_token=jwt_token
        )

    except Exception as e:
        logging.error(f"Generation Error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Account Generation Failed: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
