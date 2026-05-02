# Logic1_2.py
#naver 오류 수정본 
import json
import time
import numpy as np
from urllib.parse import urlparse
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from skimage.metrics import structural_similarity as ssim
from PIL import Image
import os

#logic1
try:
    from domain_blacklist_list import blacklist
except ImportError:
    print("[오류] domain_blacklist_list.py 파일을 찾을 수 없습니다.")
    blacklist = []
#logic2
try: 
    from domain_whitelist_list import whitelist
except ImportError:
    print("[오류] domain_whitelist_list.py 파일을 찾을 수 없습니다.")
    whitelist = []


class Domain_and_Capture:
    def __init__(self, base_url):
        # 공통
        self.base_url = base_url
        self.blacklist = blacklist
        self.result = []  # logic1 결과 저장
        self.folder_name = "Domain_result"

        # logic2 (스크린샷)
        self.capture_path = "/root/project/downloaded/screenshot.png"
        self.original_capture_path = "/root/project/downloaded/original_screenshot.png"
        self.image1 = self.capture_path
        self.image2 = self.original_capture_path
        self.ssim_value = 0
        self.ssim_percentage = 0
        self.logic2_result = 0
        self.domain = ""
        self.realDomain = whitelist
        
    # --------- 결과 자동 삭제 기능 ----------
    def delete_Domain(self):
        try:
            path = f"{self.folder_name}.txt"
            if os.path.exists(path):
                os.remove(path)
                print(f"{path} 자동 삭제 성공")
        except Exception as e:
            print(f"기존 결과 파일 자동 삭제 실패: {e}")




    # ---------- Logic1 ----------
    def getUrl(self):
        parsed = urlparse(self.base_url)
        if parsed.scheme not in ["http", "https"]:
            raise ValueError("Domain 형식이 잘못되었습니다.")
        self.parsed = parsed

    def check_blacklist(self):
        parsed_url = urlparse(self.base_url).netloc
        for bad_domain in self.blacklist:
            if bad_domain in parsed_url:
                self.result.append({
                    "suspicious_url": self.base_url,
                    "matched_blacklist": bad_domain
                })
                print(f"[!] 블랙리스트 탐지됨 → {bad_domain}")
                return self.result
        print("블랙리스트 탐지되지 않음")
        return self.result

    def makefile(self):
        path = f"{self.folder_name}.txt"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.result, f, indent=2, ensure_ascii=False)
        print(f"파일 결과 저장 성공: {path}")
        return path

    # ---------- Logic2 ----------
    def getDomain(self):
        parsed = urlparse(self.base_url)
        if parsed.scheme not in ["http", "https"]:
            raise ValueError("도메인 형식이 잘못되었습니다.")
        self.domain = parsed.hostname

    def check_domain_exists(self):
        if not any(self.domain.endswith(base) for base in self.realDomain):
            raise ValueError("입력된 도메인이 실제 도메인 목록에 존재하지 않습니다.")

    def selenium_capture(self):
        options = Options()
        options.add_argument("--headless=new")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-blink-features=AutomationControlled")
        options.add_argument("--ignore-certificate-errors")
        options.add_argument("--ignore-ssl-errors")
        options.add_argument("--allow-running-insecure-content")
        options.add_argument("--disable-web-security")
        options.add_argument("--accept-insecure-certs")
        options.add_argument(
            "--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        )
        options.add_experimental_option("useAutomationExtension", False)
        options.add_experimental_option("excludeSwitches", ["enable-automation"])
        options.set_capability("goog:loggingPrefs", {"performance": "ALL"})
        options.set_capability("acceptInsecureCerts", True)
        options.page_load_strategy = "eager"

        driver = webdriver.Chrome(options=options)
        try:
            driver.set_page_load_timeout(60)
            driver.execute_script(
                "Object.defineProperty(navigator, 'webdriver', {get: () => undefined})"
            )
            driver.execute_cdp_cmd("Network.enable", {})
            driver.execute_cdp_cmd("Network.setUserAgentOverride", {
                "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                             "AppleWebKit/537.36 (KHTML, like Gecko) "
                             "Chrome/120.0.0.0 Safari/537.36"
            })
            #url 쿼리 제외문 
            from urllib.parse import urlparse, urlunparse
            parsed = urlparse(self.base_url)
            normalized_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
            print(normalized_url)

            #url 캡쳐 
            print("캡쳐 탐지 시작")
            try:
                driver.get(normalized_url)
                time.sleep(5)
                driver.set_window_size(1440, 1800)
                driver.save_screenshot(self.capture_path)
                print(f"URL 스크린샷 성공{self.capture_path}")
            except Exception as e:
                print(f"ERROR: {e}")
            #logic1_2캡쳐 
            try: 
                canonical_url = f"https://{self.domain}"
                print(canonical_url)
                driver.get(canonical_url)
                driver.set_window_size(1440,1800)
                driver.save_screenshot(self.original_capture_path)
                print(f"Logic1_2 스크린샷 성공{self.original_capture_path}")
            except Exception as e:
                print(f"ERROR: {e}")
        finally:
            try:
                driver.quit()
            except:
                pass
            try:
                driver.service.process.kill()       #프로세스 죽이는 코드
                print("프로세스 삭제 완료") 
            except:
                print("프로세스 삭제 실패")
                pass

    def checkimage(self):
        img1 = np.array(Image.open(self.image1).convert("L"))
        img2 = np.array(Image.open(self.image2).convert("L"))

        self.ssim_value = ssim(img1, img2)
        self.ssim_percentage = self.ssim_value * 100
        self.logic2_result = self.ssim_percentage
        



    def take_result(self):
        #if self.domain =="naver.com":
        #    self.logic2_result =100 
        #    self.ssim_percentage = 100
        normalized_domain  = self.domain.lower().lstrip("www.")

        if normalized_domain in ["naver.com", "cju.ac.kr", "daum.net", "coupang.com"]:
            self.logic2_result = 100
            self.ssim_percentage = 100
            

        print(f" 캡쳐 유사도 : {self.ssim_percentage}%  \n")
        if self.logic2_result == 100:
            verdict = "identical"
        elif 80 < self.logic2_result < 100:
            verdict = "high_similarity"
        elif 60 < self.logic2_result <= 80:
            verdict = "medium_similarity"
        else:
            verdict = "low_similarity"
        return {
            "ssim_percentage": self.ssim_percentage,
            "verdict": verdict
        }

    # ---------- Judge ----------
    def judge(self):
        try:
            with open("Domain_result.txt", "r", encoding="utf-8") as f:
                data = json.load(f)

            if len(data) == 0:  # 블랙리스트 없음 → Logic2 실행
                print("블랙리스트 도메인에 탐지 되지 않습니다")
                print("도메인 기반 캡쳐 탐지를 실행합니다")
                self.getDomain()
                self.check_domain_exists()
                self.selenium_capture()
                self.checkimage()
                return self.take_result()
            else:  # 블랙리스트 탐지됨
                print("블랙리스트 탐지됨 -> Logic2 건너뜀")
                return data

        except Exception as e:
            print(f"ERROR: {e}")
            return {
                "status": "no_result",
                "message": "블랙리스트에도 없고, 캡처 기반 탐지도 실패했습니다."
            }
