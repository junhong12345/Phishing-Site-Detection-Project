#UrlLoader 모듈화 version
#naver 오류 수정본
import os, re, json, base64, time, shutil, platform, subprocess
from urllib.parse import urlparse, urlsplit, parse_qsl
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

#스태가노그래피 lib
from PIL import Image, PngImagePlugin
from mutagen.mp3 import MP3
from mutagen.mp4 import MP4
from mutagen.id3 import ID3, TXXX, COMM, USLT
import brotli

def ping_host(host: str) -> bool:
    system = platform.system()
    cmd = ["ping", "-n", "1", host] if system == "Windows" else ["ping", "-c", "1", host]
    try:
        res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return res.returncode == 0
    except Exception:
        return False

class UrlLoader:
    def __init__(self, base_url: str):
        self.base_url = (base_url or "").strip()
        self.parsed = urlparse(self.base_url)
        self.folder_name = "downloaded"
        BASE_DIR = os.path.dirname(os.path.abspath(__file__))
        self.SAVE_DIR = os.path.join(BASE_DIR, self.folder_name)
        self.host = self.parsed.hostname or ""
        self.capture_path = os.path.join(self.SAVE_DIR, "screenshot.png")
        self.OUT_JSON = os.path.join(BASE_DIR, "network_log.json")

        self.SENSITIVE = re.compile(
            r"(password|pass|pwd|otp|code|token|csrf|session|auth|email|username|account)",
            re.I
        )
        self.network_rows = []
        
        #JS 탐지 패턴
        self.js_regexes = [
    # document.write(...)
    re.compile(r'(?<![\w$])document\s*(?:\.\s*write|\[\s*["\']write["\']\s*\])\s*\(', re.I),

    # innerHTML 대입
    re.compile(r'(?<![\w$])(?:[A-Za-z_$][\w$]*|\))\s*(?:\.\s*innerHTML|\[\s*["\']innerHTML["\']\s*\])\s*=', re.I),

    # insertAdjacentHTML(...)
    re.compile(r'(?<![\w$])(?:[A-Za-z_$][\w$]*|\))\s*(?:\.\s*insertAdjacentHTML|\[\s*["\']insertAdjacentHTML["\']\s*\])\s*\(', re.I),

    # fetch(...) / sendBeacon(...)
    re.compile(r'(?<![\w$])(?:(?:window\s*\.\s*)?fetch|sendBeacon|window\s*\[\s*["\']fetch["\']\s*\])\s*\(', re.I),

    # XMLHttpRequest 생성
    re.compile(r'(?<![\w$])(?:new\s+(?:window\s*\.\s*)?XMLHttpRequest\b|XMLHttpRequest\b)', re.I),

    # window.location 대입
    re.compile(r'(?<![\w$])(?:(?:window\s*\.\s*)?location|window\s*\[\s*["\']location["\']\s*\]|location)\s*(?:\.\s*href|\[\s*["\']href["\']\s*\])?\s*=', re.I),

    # eval(atob(...)) 형태
    re.compile(r'eval\s*\(\s*atob\s*\(', re.I),

    # document.write(innerHTML) 특수 케이스
    re.compile(r'document\s*\.write\s*\(\s*.*innerHTML.*\)', re.I),
]

    def _mask_kv(self, d: dict) -> dict:
        out = {}
        for k, v in (d or {}).items():
            try:
                sv = "" if v is None else str(v)
                if self.SENSITIVE.search(k) or self.SENSITIVE.search(sv):
                    out[k] = "***"
                else:
                    out[k] = v
            except Exception:
                out[k] = v
        return out

    def _parse_body(self, post_data: str) -> dict:
        post_data = (post_data or "").strip()
        ret = {"form": {}, "json": {}, "raw_body_len": len(post_data)}
        if not post_data:
            return ret
        if (post_data.startswith("{") and post_data.endswith("}")) or (post_data.startswith("[") and post_data.endswith("]")):
            try:
                j = json.loads(post_data)
                if isinstance(j, dict):
                    ret["json"] = self._mask_kv(j)
                    return ret
            except Exception:
                pass
        try:
            pairs = dict(parse_qsl(post_data, keep_blank_values=True))
            ret["form"] = self._mask_kv(pairs)
        except Exception:
            pass
        return ret
    
    def delete_network_log(self):
        path = '/root/project/network_log.json'
        try:
            if os.path.exists(self.OUT_JSON):
                os.remove(self.OUT_JSON)
                print(f"기존 결과 Network_log 파일 삭제 완료: {path}")
        
        except Exception as e:
            print(f"ERROR: {e}")

    def delete_steganography(self):
        stegano_path = os.path.join(self.SAVE_DIR, "steganography.txt")
        try:
            if os.path.exists(stegano_path): 
                os.remove(stegano_path)
                print(f"기존 {stegano_path}결과 파일 삭제 완료")
        except Exception as e:
            print(f"ERROR: {e}")

    def make_folder(self):
        if os.path.exists(self.SAVE_DIR):
            shutil.rmtree(self.SAVE_DIR)
            print("기존 폴더 삭제")
        os.makedirs(self.SAVE_DIR, exist_ok=True)
        print("새 폴더 생성 완료")

    def getUrl(self):
        if self.parsed.scheme not in ("http", "https") or not self.parsed.netloc:
            raise ValueError("URL 형식이 잘못되었습니다.")

    def testPing(self):
        if not self.host:
            return
        if not ping_host(self.host):
            print("핑 응답 없음(차단 가능). 계속 진행.")
        else:
            print("유효한 URL/핑 응답 OK")

    def _new_driver(self):
        options = Options()
        options.add_argument("--headless=new")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-blink-features=AutomationControlled")
        options.add_argument("--ignore-certificate-errors")
        options.add_argument("--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
        options.add_experimental_option("useAutomationExtension", False)
        options.add_experimental_option("excludeSwitches", ["enable-automation"])
        options.set_capability('goog:loggingPrefs', {'performance': 'ALL'})
        options.set_capability('acceptInsecureCerts', True)

        driver = webdriver.Chrome(options=options)
        driver.set_page_load_timeout(60)
        driver.execute_cdp_cmd("Network.enable", {})
        driver.execute_cdp_cmd("Page.enable", {})
        driver.execute_cdp_cmd("Network.setCacheDisabled", {"cacheDisabled": True})
        driver.execute_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
        return driver

    def download_page_resources(self):
        self.delete_network_log()
        self.delete_steganography()
        self.make_folder()  
        self.getUrl()
        self.testPing()

        driver = self._new_driver()
        origin_host = urlparse(self.base_url).netloc
        print(f"접속 중: {self.base_url}")
        driver.get(self.base_url)
        time.sleep(5)
        #캡쳐
        try:
            driver.set_window_size(1440,1800)
            driver.save_screenshot(self.capture_path)
            print(f"캡쳐 성공 {self.capture_path}")
        except Exception as e:
            print(f"캡쳐 실패: {e}")

        try:
            with open(os.path.join(self.SAVE_DIR, "index.html"), "w", encoding="utf-8") as f:
                f.write(driver.page_source)
        except Exception as e:
            print(f"index.html 저장 실패: {e}")

        try:
            perf_logs = driver.get_log('performance')
            messages = [json.loads(entry['message'])['message'] for entry in perf_logs]
            req_map, resp_map, redirects = {}, {}, {}

            for msg in messages:
                method = msg.get("method")
                params = msg.get("params", {})
                if method == "Network.requestWillBeSent":
                    rid = params.get("requestId")
                    req = params.get("request", {}) or {}
                    doc_url = params.get("documentURL", "")
                    if params.get("redirectResponse"):
                        prev = redirects.get(rid, [])
                        prev.append(params["redirectResponse"].get("url", ""))
                        redirects[rid] = prev
                    req_map[rid] = {
                        "url": req.get("url", ""),
                        "method": req.get("method", ""),
                        "type": params.get("type") or "other",
                        "postData": req.get("postData", ""),
                        "documentURL": doc_url,
                        "ts": time.time(),
                    }
                elif method == "Network.responseReceived":
                    rid = params.get("requestId")
                    resp = params.get("response", {}) or {}
                    resp_map[rid] = {
                        "status": resp.get("status"),
                        "url": resp.get("url"),
                        "mimeType": resp.get("mimeType", "")
                    }

            for rid, resp in resp_map.items():
                try:
                    body = driver.execute_cdp_cmd("Network.getResponseBody", {"requestId": rid})
                except Exception:
                    body = None
                url = (resp.get("url") or "").strip()
                if not url:
                    continue
                path = urlparse(url).path
                name = os.path.basename(path) or f"file_{abs(hash(url))%100000}"
                mime = resp.get("mimeType", "")
                if "." not in name:
                    if "javascript" in mime:
                        name += ".js"
                    elif "css" in mime:
                        name += ".css"
                    elif "html" in mime:
                        name += ".html"
                if body and "body" in body:
                    save_path = os.path.join(self.SAVE_DIR, name)
                    try:
                        if body.get("base64Encoded"):
                            with open(save_path, "wb") as f:
                                f.write(base64.b64decode(body["body"]))
                        else:
                            with open(save_path, "w", encoding="utf-8", errors="ignore") as f:
                                f.write(body["body"])
                        print(f"저장됨: {name}")
                    except Exception:
                        pass

            rows = []
            for rid, req in req_map.items():
                rurl = req.get("url", "")
                parsed = urlsplit(rurl)
                query = dict(parse_qsl(parsed.query))
                post_info = self._parse_body(req.get("postData", ""))
                resp = resp_map.get(rid, {})
                row = {
                    "ts": req.get("ts", time.time()),
                    "origin": origin_host,
                    "method": req.get("method", ""),
                    "url": rurl,
                    "host": parsed.netloc,
                    "resource_type": req.get("type") or "other",
                    "status": resp.get("status"),
                    "cross_domain": (parsed.netloc != "" and parsed.netloc != origin_host),
                    "redirect_chain": redirects.get(rid, []),
                    "query": self._mask_kv(query),
                    "form": post_info["form"],
                    "json": post_info["json"],
                    "raw_body_len": post_info["raw_body_len"],
                    "frame_url": req.get("documentURL", "")
                }
                rows.append(row)

            with open(self.OUT_JSON, "w", encoding="utf-8") as f:
                json.dump(rows, f, ensure_ascii=False, indent=2)
            self.network_rows = rows
            print(f"[OK] 네트워크 로그 {len(rows)}건 저장 → {self.OUT_JSON}")

        except Exception as e:
            print(f"[WARN] 네트워크 로그 수집 실패: {e}")

        driver.quit()
        print("리소스 다운로드 완료\n")

    def extract_javascript(self):
        folder_path = self.SAVE_DIR
        seen = set()
        patterns = [
            r'<script[^>]*>(.*?)</script>',
            r'<script\s+[^>]*src\s*=\s*["\'](.*?)["\']',
            r'<iframe\s+[^>]*src\s*=\s*["\'](.*?)["\']',
            r'<iframe[^>]*>(.*?)</iframe>',
            r'(?:function\s+\w+\s*\([^)]*\)\s*\{[^}]*\}|(?:var|let|const)\s+\w+\s*=\s*[^;]+;|[\w.]+\s*=\s*function[^}]*\})'
        ]
        excluded_exts = {'.jpg', '.jpeg', '.png', '.mp4', '.mp3', '.woff', '.woff2'}
        js_blocks = []
        for fname in os.listdir(folder_path):
            fpath = os.path.join(folder_path, fname)
            if not os.path.isfile(fpath):
                continue
            if os.path.splitext(fname)[1].lower() in excluded_exts:
                continue
            try:
                content = open(fpath, 'r', encoding='utf-8', errors='ignore').read()
            except Exception:
                continue
            unique_blocks = []
            for p in patterns:
                for block in re.findall(p, content, re.DOTALL | re.IGNORECASE | re.MULTILINE):
                    b = (block or "").strip()
                    if b and b not in seen:
                        seen.add(b)
                        unique_blocks.append(b)
            if unique_blocks:
                js_blocks.append(f"\n// ==== {fname} ====\n" + "\n".join(unique_blocks))
        combined_path = os.path.join(folder_path, "combined.txt")
        with open(combined_path, 'w', encoding='utf-8') as f:
            f.write("==================")
            f.write(''.join(js_blocks))
        print(f"JS 블록 {len(js_blocks)}개 추출 완료")


    def extract_matches(self, texts):
        results = []
        for t in texts:
            for r in self.js_regexes:
                if r.search(t):
                    results.append(t.strip())
                    break
        return results

    def scan_steganography(self):
        report = []
        for fname in os.listdir(self.SAVE_DIR):
            path = os.path.join(self.SAVE_DIR, fname)
            ext = os.path.splitext(fname)[1].lower().strip(".")
            if not os.path.isfile(path):
                continue
            findings = []
            try:
                if ext == "png":
                    img = PngImagePlugin.PngImageFile(path)
                    findings = self.extract_matches(img.text.values())
                elif ext in ("jpg", "jpeg"):
                    img = Image.open(path)
                    exif_data = [str(v) for v in img.getexif().values()]
                    findings = self.extract_matches(exif_data)
                elif ext == "mp3":
                    audio = MP3(path, ID3=ID3)
                    texts = [str(f.text) for f in audio.tags.values() if isinstance(f, (TXXX, COMM, USLT))]
                    findings = self.extract_matches(texts)
                elif ext == "mp4":
                    audio = MP4(path)
                    findings = self.extract_matches(map(str, audio.tags.values()))
                elif ext in ("woff", "woff2"):
                    with open(path, 'rb') as f:
                        data = f.read()
                    if ext == "woff2":
                        data = brotli.decompress(data)
                    if any(r.search(data.decode(errors='ignore')) for r in self.js_regexes):
                        findings = ["<binary pattern matched>"]
            except:
                pass
            if findings:
                block = f"\n// ==== {fname} ====\n\n" + "\n".join(findings)
                report.append(block)

        out_path = os.path.join(self.SAVE_DIR, "steganography.txt")
        try:
            with open(out_path, "w", encoding="utf-8") as f:
                if report:
                    f.write("\n".join(report))
                    print(f"스태가노그래피 추출 성공 → {out_path}")
                else:
                    f.write("스태가노그래피 추출 실패")
                    print(f"스태가노그래피 추출 실패 → {out_path}")
        except Exception as e:
            print(f"ERROR: {e}")

        return report

    def get_combined_path(self):
        return os.path.join(self.SAVE_DIR, "combined.txt")
