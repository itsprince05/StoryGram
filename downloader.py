import os
import sys
import re
import time
import shutil
import platform
import subprocess
import zipfile
import xml.etree.ElementTree as ET
import urllib3
import requests

from get_keys import fetch_widevine_keys

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

COLORS = {
    'INFO': "\033[36m",
    'SUCCESS': "\033[32m",
    'ERROR': "\033[31m",
    'WARN': "\033[33m",
    'STEP': "\033[35m",
    'RESET': "\033[0m"
}

def log_msg(msg: str, msg_type: str = 'INFO'):
    timestamp = time.strftime('%H:%M:%S')
    color = COLORS.get(msg_type, COLORS['RESET'])
    reset = COLORS['RESET']
    print(f"{color}[{timestamp}] [{msg_type}] {msg}{reset}", flush=True)

def find_or_download_mp4decrypt() -> str:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    bin_name = "mp4decrypt.exe" if platform.system() == "Windows" else "mp4decrypt"
    local_path = os.path.join(script_dir, bin_name)

    if os.path.exists(local_path):
        if platform.system() != "Windows":
            try:
                os.chmod(local_path, 0o755)
            except:
                pass
        return local_path

    which_path = shutil.which(bin_name)
    if which_path:
        return which_path

    # If on Linux and missing, auto-download Bento4 Linux binaries
    if platform.system() == "Linux":
        log_msg("mp4decrypt not found. Auto-downloading Linux binary from bok.net...", 'INFO')
        try:
            zip_url = "https://www.bok.net/Bento4/binaries/Bento4-SDK-1-6-0-641.x86_64-unknown-linux.zip"
            headers = {"User-Agent": "Mozilla/5.0"}
            res = requests.get(zip_url, stream=True, headers=headers, timeout=30)
            if res.status_code == 200:
                zip_path = os.path.join(script_dir, "bento4.zip")
                with open(zip_path, "wb") as f:
                    for chunk in res.iter_content(8192):
                        f.write(chunk)

                with zipfile.ZipFile(zip_path, "r") as zip_ref:
                    for member in zip_ref.namelist():
                        if member.endswith("mp4decrypt"):
                            with zip_ref.open(member) as source, open(local_path, "wb") as target:
                                shutil.copyfileobj(source, target)
                            break

                os.chmod(local_path, 0o755)
                if os.path.exists(zip_path):
                    os.remove(zip_path)
                log_msg("Successfully downloaded and extracted Linux mp4decrypt!", 'SUCCESS')
                return local_path
        except Exception as e:
            log_msg(f"Failed to auto-download Linux mp4decrypt: {e}", 'WARN')

    return None

def download_file(url: str, output_path: str) -> bool:
    log_msg(f"Downloading: {os.path.basename(output_path)}...")
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }

    try:
        with requests.get(url, headers=headers, stream=True, verify=False, timeout=300) as response:
            response.raise_for_status()
            total_size = int(response.headers.get('content-length', 0))
            downloaded = 0
            os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
            with open(output_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=65536):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)

        size_mb = round(os.path.getsize(output_path) / 1048576, 2)
        log_msg(f"Downloaded: {size_mb} MB", 'SUCCESS')
        return True
    except Exception as e:
        log_msg(f"Download failed: {e}", 'ERROR')
        if os.path.exists(output_path):
            try:
                os.remove(output_path)
            except Exception:
                pass
        return False

def parse_mpd(mpd_content: str, quality: str = "64k") -> dict:
    try:
        clean_xml = re.sub(r'\sxmlns="[^"]+"', '', mpd_content, count=1)
        root = ET.fromstring(clean_xml)
    except Exception as e:
        log_msg(f"MPD parse error: {e}", 'ERROR')
        return None

    audio_reps = []
    for rep in root.iter('Representation'):
        mime_type = rep.attrib.get('mimeType', '')
        codecs = rep.attrib.get('codecs', '')
        base_url_elem = rep.find('BaseURL')
        base_url = base_url_elem.text.strip() if base_url_elem is not None and base_url_elem.text else ''
        bandwidth = rep.attrib.get('bandwidth', '')

        is_audio = mime_type.startswith('audio') or 'mp4a' in codecs or 'audio' in base_url.lower()
        if is_audio and base_url:
            audio_reps.append({
                'file': base_url,
                'bandwidth': bandwidth,
                'codec': codecs
            })

    if not audio_reps:
        for rep in root.iter('Representation'):
            base_url_elem = rep.find('BaseURL')
            if base_url_elem is not None and base_url_elem.text:
                audio_reps.append({
                    'file': base_url_elem.text.strip(),
                    'bandwidth': rep.attrib.get('bandwidth', ''),
                    'codec': rep.attrib.get('codecs', '')
                })

    if not audio_reps:
        log_msg("No audio tracks found in MPD manifest!", 'ERROR')
        return None

    target_file = f"protected_audio_mpd_{quality}.mp4"
    for rep in audio_reps:
        if rep['file'] == target_file:
            return rep

    return audio_reps[0]

def process_download(mpd_url: str, show_id: str = None, output_name: str = None, quality: str = "64k", license_url: str = None, headers: dict = None) -> str:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    out_dir = os.path.join(script_dir, 'temp_streams')
    os.makedirs(out_dir, exist_ok=True)

    if not output_name:
        output_name = f"audio_{int(time.time())}"

    decrypted_file = os.path.join(out_dir, f"{output_name}.m4a")
    if os.path.exists(decrypted_file) and os.path.getsize(decrypted_file) > 1024:
        log_msg(f"Stream cache hit: {decrypted_file}", 'SUCCESS')
        return decrypted_file

    mp4decrypt_bin = find_or_download_mp4decrypt()
    if not mp4decrypt_bin:
        raise FileNotFoundError("mp4decrypt binary not found.")

    req_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
    mpd_resp = requests.get(mpd_url, headers=req_headers, verify=False, timeout=20)
    if mpd_resp.status_code != 200:
        raise RuntimeError(f"HTTP error fetching MPD: {mpd_resp.status_code}")

    audio_info = parse_mpd(mpd_resp.text, quality)
    if not audio_info:
        raise ValueError("Could not parse audio information from MPD manifest.")

    mpd_base_url = mpd_url.rsplit('/', 1)[0]
    audio_url = f"{mpd_base_url}/{audio_info['file']}"

    encrypted_file = os.path.join(out_dir, f"encrypted_{output_name}.mp4")
    if not download_file(audio_url, encrypted_file):
        raise RuntimeError("Failed to download encrypted audio file.")

    try:
        keys = fetch_widevine_keys(
            mpd_url=mpd_url,
            show_id=show_id,
            license_url=license_url,
            headers=headers or {},
            wvd_path=os.path.join(script_dir, "l3.wvd")
        )

        if not keys:
            raise RuntimeError("No decryption keys obtained.")

        key_args = []
        for kid, key in keys.items():
            key_args.extend(["--key", f"{kid}:{key}"])

        decrypt_cmd = [mp4decrypt_bin] + key_args + [encrypted_file, decrypted_file]
        proc = subprocess.run(decrypt_cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            raise RuntimeError(f"mp4decrypt failed: {proc.stderr}")

        ffmpeg_bin = shutil.which("ffmpeg")
        if ffmpeg_bin:
            fixed_file = os.path.join(out_dir, f"fixed_{output_name}.m4a")
            ff_proc = subprocess.run([ffmpeg_bin, "-y", "-i", decrypted_file, "-c", "copy", fixed_file], capture_output=True, text=True)
            if ff_proc.returncode == 0 and os.path.exists(fixed_file):
                try:
                    os.remove(decrypted_file)
                    os.rename(fixed_file, decrypted_file)
                except Exception:
                    pass
    finally:
        if os.path.exists(encrypted_file):
            try:
                os.remove(encrypted_file)
            except Exception:
                pass

    if os.path.exists(decrypted_file):
        return decrypted_file
    else:
        raise FileNotFoundError(f"Decrypted output file was not created: {decrypted_file}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python downloader.py <mpd_url> [show_id] [output_name] [quality]")
        sys.exit(1)

    mpd_url = sys.argv[1]
    show_id = sys.argv[2] if len(sys.argv) >= 3 and sys.argv[2] != "" else None
    output_name = sys.argv[3] if len(sys.argv) >= 4 and sys.argv[3] != "" else f"audio_{int(time.time())}"
    quality = sys.argv[4] if len(sys.argv) >= 5 and sys.argv[4] != "" else "64k"

    try:
        res = process_download(mpd_url, show_id=show_id, output_name=output_name, quality=quality)
        print(f"SUCCESS:{res}")
    except Exception as e:
        print(f"ERROR:{e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
