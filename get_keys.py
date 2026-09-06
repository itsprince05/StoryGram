import sys
import json
import requests
import re
import urllib3
import base64
import hashlib
import os
from Crypto.Cipher import AES
from pywidevine.cdm import Cdm
from pywidevine.device import Device
from pywidevine.pssh import PSSH

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def decrypt_pfm(j: int, device_id: str, cipher: str) -> bytes:
    data = f"{device_id}:{j}".encode()
    encoded = base64.b64encode(data).decode()
    chars = list(encoded)
    for i in range(0, len(chars)-1, 2):
        chars[i], chars[i+1] = chars[i+1], chars[i]
    key = "".join(chars).encode()
    d = base64.b64decode(cipher)
    salt = d[:16]
    iv = d[16:28]
    str_data = d[28:-16]
    key = hashlib.pbkdf2_hmac("sha256", key, salt, 10000, dklen=32)
    cipher_obj = AES.new(key, AES.MODE_GCM, nonce=iv)
    plaintext = cipher_obj.decrypt(str_data)
    return plaintext

def get_pfm_auth_token(show_id=None):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }
    session = requests.Session()
    session.headers.update(headers)

    urls_to_try = []
    if show_id:
        urls_to_try.extend([f"https://pocketfm.com/show/{show_id}", f"https://pocketfm.com/in/show/{show_id}"])
    urls_to_try.extend(["https://pocketfm.com/in/", "https://pocketfm.com/"])

    for url in urls_to_try:
        try:
            res = session.get(url, timeout=10, allow_redirects=True)
            if "auth-token" in session.cookies:
                return session.cookies["auth-token"]
            for r in [res] + list(res.history):
                cookie_hdr = r.headers.get("set-cookie", "")
                match = re.search(r'auth-token=([^;,\s]+)', cookie_hdr)
                if match:
                    return match.group(1)
        except Exception:
            continue

    return None

def get_pfm_license_url(show_id):
    auth_token = get_pfm_auth_token(show_id)
    device_id = "mobile-web"

    h1 = {
        "user-agent": "com.radio.pocketfm",
        "platform": "android",
        "version-name": "9.1.3",
        "platform-version": "29",
        "app-version": "2013",
        "device-id": device_id,
        "device_id": device_id,
        "client-ts": "1770000000",
        "content-type": "application/json;charset=utf-8"
    }
    h2 = {
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "platform": "web",
        "device-id": device_id,
        "device_id": device_id,
        "client-ts": "1770000000",
        "content-type": "application/json;charset=utf-8"
    }

    if auth_token:
        h1["authorization"] = f"Bearer {auth_token}"
        h1["auth-token"] = auth_token
        h2["authorization"] = f"Bearer {auth_token}"
        h2["auth-token"] = auth_token

    headers_list = [h1, h2]

    url = f"https://api.pocketfm.com/v2/content_api/show.play_details?show_id={show_id}"
    last_err = ""
    for header in headers_list:
        try:
            res = requests.get(url, headers=header, timeout=10)
            if res.status_code == 200:
                data = res.json()
                blob = data.get("blob")
                if blob:
                    wv_lic = decrypt_pfm(1770000000, device_id, blob)
                    return wv_lic.decode(), None
                last_err = f"No blob in API response. Response: {res.text[:200]}"
            else:
                last_err = f"Status {res.status_code}: {res.text[:200]}"
        except Exception as e:
            last_err = str(e)
            
    return None, f"PocketFM API failed: {last_err}"

def get_pssh(mpd_content):
    try:
        match = re.search(r"<cenc:pssh>(.*?)</cenc:pssh>", mpd_content, re.DOTALL)
        if match:
            return match.group(1).strip()
    except Exception:
        pass
    return None

def fetch_widevine_keys(mpd_url, show_id=None, license_url=None, headers=None, wvd_path=None):
    if headers is None:
        headers = {}
    if not wvd_path:
        wvd_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "l3.wvd")

    if not os.path.exists(wvd_path):
        raise FileNotFoundError(f"WVD file not found at: {wvd_path}")

    if show_id and not license_url:
        license_url, err_msg = get_pfm_license_url(show_id)
        if not license_url:
            raise RuntimeError(f"Failed to generate PocketFM license URL using show_id: {err_msg}")

    if not license_url:
        raise ValueError("No license_url or show_id provided.")

    mpd_resp = requests.get(mpd_url, headers={"User-Agent": "Mozilla/5.0"}, timeout=15, verify=False)
    if mpd_resp.status_code != 200:
        raise RuntimeError(f"Failed to fetch MPD manifest: HTTP {mpd_resp.status_code}")

    pssh_b64 = get_pssh(mpd_resp.text)
    if not pssh_b64:
        raise ValueError("No PSSH found in MPD manifest.")

    device = Device.load(wvd_path)
    cdm = Cdm.from_device(device)
    session_id = cdm.open()
    try:
        pssh = PSSH(pssh_b64)
        challenge = cdm.get_license_challenge(session_id, pssh)
        lic_resp = requests.post(license_url, headers=headers, data=challenge, timeout=15, verify=False)
        if lic_resp.status_code != 200:
            raise RuntimeError(f"License request failed (HTTP {lic_resp.status_code}): {lic_resp.text[:200]}")

        cdm.parse_license(session_id, lic_resp.content)

        keys = {}
        for key in cdm.get_keys(session_id):
            if key.type == 'CONTENT':
                keys[key.kid.hex] = key.key.hex()

        if not keys:
            raise RuntimeError("No CONTENT keys returned by CDM.")

        return keys
    finally:
        try:
            cdm.close(session_id)
        except Exception:
            pass

def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Missing config JSON argument"}))
        sys.exit(1)

    try:
        b64_config = sys.argv[1]
        config_str = base64.b64decode(b64_config).decode('utf-8')
        config = json.loads(config_str)
        mpd_url = config.get("mpd_url")
        show_id = config.get("show_id")
        wvd_path = config.get("wvd_path", os.path.join(os.path.dirname(os.path.abspath(__file__)), "l3.wvd"))
        lic_url = config.get("license_url")
        headers = config.get("headers", {})

        keys = fetch_widevine_keys(mpd_url=mpd_url, show_id=show_id, license_url=lic_url, headers=headers, wvd_path=wvd_path)
        print(json.dumps({"success": True, "keys": keys}))
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)

if __name__ == "__main__":
    main()
