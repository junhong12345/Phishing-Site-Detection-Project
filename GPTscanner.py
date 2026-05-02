# GPTScanner 모듈화 version
# 결과 출력 추가 
from openai import OpenAI
import time, os, sys, logging, json, re

# --- stdout/stderr 인코딩 (환경 따라 생략 가능) ---
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

class GPTScanner:
    def __init__(self):
        self.client = OpenAI(api_key="API_KEY")
        self.model_name = "gpt-4o-mini"

        # 청크 크기(문자 기준)
        self.max_len = 50000

        # 내부 상태
        self.final_result: list[str] = []
        self.full_code = ""
        self.chunks: list[str] = []

        # 경로
        self.total_path = "/root/project"
        self.downloaded_path = os.path.join(self.total_path, "downloaded")
        self.combined_path = os.path.join(self.downloaded_path, "combined.txt")
        self.result_txt_path = os.path.join(self.total_path, "gpt_result.txt")
        self.result_json_path = os.path.join(self.total_path, "gpt_result.json")
        self.result_score_path = os.path.join(self.total_path, "gpt_result_score.json")

        # httpx(내부) 소음 줄이기
        logging.getLogger("httpx").setLevel(logging.WARNING)


    def delete_file(self):
        for path in [self.result_json_path, self.result_txt_path, self.result_score_path]:
            if os.path.exists(path) and os.path.isfile(path):
                try:
                    os.remove(path)
                    print(f"{path} 파일 삭제 완료")
                except Exception as e:
                    print(f"ERROR : {e}")
        
        


    def load_file(self):
        target = self.combined_path
        if os.path.exists(self.combined_path) and os.path.isfile(self.combined_path):
            while True:
                try:
                    with open(target, "r", encoding="utf-8", errors="ignore") as f:
                        self.full_code = f.read()
                        print(f"{self.combined_path} 파일 불러오기 성공")
                    break
                except Exception as e:
                    print(f" 파일 열기 실패 ({target}): {e}")

            print(f"[INFO] 읽은 파일 크기: {len(self.full_code)} bytes")
            self.chunks = [self.full_code[i:i+self.max_len] for i in range(0, len(self.full_code), self.max_len)]
            print(f"[INFO] 총 {len(self.chunks)}개의 조각으로 분할 완료\n")

    def analyze_chunks(self):
        SYSTEM_PROMPT = (
"역할: 웹 피싱 탐지 분석가. 입력은 한 사이트의 JS/HTML 일부다.\n"
"판정은 '코드에 보이는 증거'만으로 하라(추정 금지). 아래 '특성(Features)'과 '결정 규칙'으로만 결론을 내리고, 지정된 JSON만 출력한다.\n"
#"또한, 입력된 JS/HTML에서 **난독화된 부분만 복호화**하고, **난독화되지 않은 부분은 그대로 유지**."
"\n"
"[특성 카테고리 및 가중치]\n"
"CRITICAL (가중치=50):\n"
"  F1 지갑/시드 수집(일반 비밀번호·OTP 제외): seed phrase|secret recovery phrase|mnemonic|private key|keystore(UTC/JSON)|recovery phrase\n"
"  F2 외부 유출(절대/해석된 URL): discord.com/api/webhooks|api.telegram.org|script.google.com/macros/s/|forms.gle|formspree.io|getform.io|web3forms.com\n"
"     혹은 코드에서 문자열 결합/템플릿을 거쳐 **http(s)://호스트/** 로 해석되는 fetch/XHR/form 전송\n"
"  F3 난독→네트워크(강한 조건만 인정): (A,B 모두 충족)\n"
"     A) atob/fromCharCode/\\x/\\u/hex 중 2개 이상 + 120자↑ 인코딩 페이로드\n"
"     B) 인접 블록/함수 내에 fetch/XHR/form/redirect 호출 존재\n"
"  F4 수취용 식별자 하드코딩: 지갑 주소(0x…40hex)/텔레그램 봇 토큰(bot\\d{9,}:)/웹훅 URL 등\n"
"\n"
"HIGH (가중치=25):\n"
"  F5 브랜드 사칭+인증(브랜드 ‘인접’ 조건): (metamask|trezor|ledger|binance|coinbase|phantom|trust wallet) **±80자 내** (login|signin|verify|connect|restore|recover)\n"
"  F6 리다이렉트/유도: location.replace/href/window.open 등으로 **외부 절대/해석된 URL** 이동\n"
"  F7 지갑 연결 위장: walletconnect/metamask API를 흉내 내 seed/secret/리커버리 문구 요구\n"
"\n"
"[거짓양성(정상) 패턴 — 반드시 제외]\n"
"- 분석/로그/광고: gtag, google-analytics, googletagmanager, yandex, hotjar, matomo, mixpanel, amplitude, sentry, rollbar, logrocket\n"
"- 일반 CDN/라이브러리/에셋: cdn.jsdelivr, unpkg, cdnjs, googleapis, bootstrap, jquery, fontawesome, react, vue, angular, svelte, tailwind\n"
"- 번들러/런타임: webpack, parcel, vite, __NEXT_DATA__, require/define,module.exports,System.register\n"
"- 보안/봇/동의: recaptcha(.net|.google.com), hcaptcha.com, cookieconsent, i18n 로드\n"
"- 공식 OAuth/결제/로그인 **단독**: accounts.google.com, appleid.apple.com, github.com/login/oauth, api.stripe.com, paypal.com 등은 단독 근거 아님\n"
"- eval/new Function **단독**은 근거 아님(F3 A+B 동시 충족 시에만 인정)\n"
"\n"
"[의심 상대경로(좁힘)]  login.php, send.php, auth.php, verify.php\n"
"\n"
"[결정 규칙(가중치 + 조합)]\n"
"- 즉시 phishing:\n"
"  R1: F1 ∧ (F2 ∨ F6)  # 외부 절대/해석된 URL\n"
"  R2: F2 ∧ (F5 ∨ F6)\n"
"  R3: F3 ∧ (F2 ∨ F6)\n"
"  R4: F4 ∧ (F2 ∨ F6)\n"
"- 보완(상대경로):\n"
"  R1b: F1 ∧ F6 with 상대경로 AND 경로에 [의심 상대경로] 중 하나 포함\n"
"- 누적 점수(Σ 가중치):\n"
"  · Σ≥75 이고 최소 1개가 (F2 또는 F6)일 때 phishing\n"
"  · Σ≥50 이고 (F1 또는 F4) 포함 **그리고** (F6 또는 [의심 상대경로]) 동반 시 phishing\n"
"    (단, 두 신호(F1/F4와 F6/의심경로)가 동일 청크 내에 없으면 confidence를 0.55 이하로 제한)\n"
"- 그 외는 benign. 애매하면 reasons에 '증거 부족/동일 출처/변수 URL' 등을 명시하고 confidence 0.25~0.45.\n"
"\n"
"[출력 형식 — 반드시 JSON만 출력]\n"
"{\n"
"  \"verdict\": \"phishing\" | \"benign\",\n"
"  \"confidence\": float(0.0~1.0, 소수 둘째 자리),\n"
"  \"rules_triggered\": [\"R1\",\"F2\",\"F6\"],\n"
"  \"risk_score\": int(Σ 가중치 합계),\n"
"  \"reasons\": [\"Fx/Rx - 설명 - '코드스니펫'\"],\n"
"  \"evidence\": {\"obfuscation\":[], \"network_calls\":[], \"forms\":[], \"redirects\":[]}\n"
"}\n"
"규칙: JSON 외 텍스트 금지. benign이면 risk_score=0, rules_triggered=[], confidence ≤ 0.4.\n"
)

        total = len(self.chunks)
        for idx, chunk in enumerate(self.chunks, 1):
            print(f"[{idx}/{total}] 조각 이중 분석 중...")
            meaningful_result: str | None = None

            for trial in range(2):  
                retries = 0
                while retries < 3:
                    try:
                        resp = self.client.chat.completions.create(
                            model=self.model_name,
                            messages=[
                                {"role": "system", "content": SYSTEM_PROMPT},
                                {"role": "user", "content": chunk}
                            ],
                            temperature=0.0,
                        )
                        result = (resp.choices[0].message.content or "").strip()
                        print(f"    [시도 {trial+1}] 분석 완료")

                        # 유의미성: 빈 JSON/빈 문자열/고정 에러문구 제외
                        if result not in ("{}", "", "에러 발생"):
                            meaningful_result = result
                        break

                    except Exception as e:
                        err = str(e)
                        print(f"    [시도 {trial+1}] 분석 실패 (재시도 {retries+1}): {err}")
                        if ("429" in err) or ("rate" in err.lower()) or any(x in err for x in ("502","503","504","timeout","temporarily","unavailable")):
                            wait = max(1, 2 ** retries)
                            print(f"      → 제한/일시오류: {wait}초 대기")
                            
                            time.sleep(wait)
                            retries += 1
                        else:
                            meaningful_result = "{}"  # 비재시도성 에러는 빈 JSON 처리
                            break
                
                time.sleep(0.8)
                if meaningful_result:
                    break

            self.final_result.append(meaningful_result or "{}")

    
    #이건요구사항에 해당 x
    @staticmethod
    def _safe_parse_json(text: str):
        """응답이 코드블록/잡텍스트 섞여도 JSON만 뽑아서 파싱"""
        m = re.search(r"\{.*\}", text, re.DOTALL)
        if not m:
            return None
        try:
            return json.loads(m.group(0))
        except Exception:
            return None

    def save_json_results(self):
        """
        하나의 gpt_result.json에 'chunks' 배열로 저장.
        - 각 요소는 파싱 성공 시 dict, 실패 시 raw 문자열.
        """
        os.makedirs(os.path.dirname(self.result_json_path), exist_ok=True)
        json_items = []
        for res in self.final_result:
            parsed = self._safe_parse_json(res)
            json_items.append(parsed if parsed is not None else {"raw": res})

        payload = {"chunks": json_items}
        with open(self.result_json_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        print(f"[INFO] JSON 저장: {self.result_json_path}")

    
    
    def take_score(self):
        try:
            if os.path.exists(self.result_json_path) and os.path.isfile(self.result_json_path):
                with open(self.result_json_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    print(f"{self.result_json_path} 파일 불러오기 성공")

                phishing_results = {}

                for i, chunk in enumerate(data.get("chunks", []), 1):
                    if isinstance(chunk, dict) and chunk.get("verdict") == "phishing":
                        phishing_results[f"chunk_{i}"] = {
                            "rules_triggered": chunk.get("rules_triggered", []),
                            "risk_score": chunk.get("risk_score", 0)
                        }

                with open(self.result_score_path, "w", encoding="utf-8") as f:
                    json.dump(phishing_results, f, ensure_ascii=False, indent=2)

                print(f"[INFO] 피싱 점수 저장: {self.result_score_path}")

        except Exception as e:
            print(f"ERROR: {e}")


