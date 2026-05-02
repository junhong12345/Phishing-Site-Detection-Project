import os, re, json

class JS_Detector:
    def __init__(self,
                 combined_path="/root/project/downloaded/combined.txt",
                 result_txt_path="/root/project/JS_Detector_result.txt",
                 result_json_path="/root/project/JS_Detector_result.json"):
        self.content = ''
        self.result = {}
        self.result_txt_path = result_txt_path
        self.result_json_path = result_json_path
        self.combined_path = combined_path
        self.WINDOW = 150

        self.SENSITIVE_RE = re.compile(
            r'(password|passwd|pwd|otp|mfa|2fa|code|token|csrf|session|auth|login|signin|credential|email|username|account)',
            re.IGNORECASE
        )

        strong_patterns_raw = [
            r'https?://api\.telegram\.org/bot[^\s\'"]+',    #냅두기 
            r'https?://discord\.com/api/webhooks/[^\s\'"]+',    #냅두기 
            r'<meta[^>]+http-equiv\s*=\s*["\']refresh["\'][^>]+content\s*=\s*["\']\s*[0-5]\s*;\s*url\s*=\s*[^"\']+["\']',
            r'<form[^>]+action\s*=\s*["\']https?://[^"\']+["\']',
            r'location\.(?:href|assign|replace)\s*=\s*["\']https?://[^"\']+["\']',  #냅두기 
            r'location\.(?:href|assign|replace)\s*=\s*["\']https?://\d{1,3}(?:\.\d{1,3}){3}[^"\']*["\']',   #냅두기 
            r'(?:sendmail|mail|smtp|gate|result|post|process)\.php'     #냅두기 
        ]
        weak_patterns_raw = [   #이 패턴에 뭔가 숨겨져 있지 않을까? # 목적 성은 ai 한테 탐지하기 
            r'input[^>]+type\s*=\s*["\']password["\']',
            r'\.open\s*\(\s*["\'](?:GET|POST)["\']\s*,\s*["\']https?://',
            r'ip-api\.com|api\.ipify\.org|ipinfo\.io/json',
            #r'(?<![\w$])(?:new\s+(?:window\s*\.\s*)?XMLHttpRequest\b|XMLHttpRequest\b)',  # XMLHttpRequest
            r'(?<![\w$])document\s*\.\s*write\s*\(\s*innerHTML\s*\)',
            r'(?<![\w$])eval\s*\(\s*atob\s*\(',
            r'addEventListener\s*\(\s*["\']submit["\']',
            r'(?:fetch|sendBeacon)\s*\(\s*["\']https?://',
            # document.write(...)
            r'(?<![\w$])document\s*(?:\.\s*write|\[\s*["\']write["\']\s*\])\s*\(',
            # innerHTML (대입 상황만 잡음)  #innerHTML를 ai가 잘 잡아낸다면 logic3에서 innerhtml을 제외하고 ai한테만 탐지하게 함(오탐이 많아서 )
            r'(?<![\w$])(?:[A-Za-z_$][\w$]*|\))\s*(?:\.\s*innerHTML|\[\s*["\']innerHTML["\']\s*\])\s*=',    #inner 를 빼고 다른 걸 찾아야 하나? # inner를 빼면 안됨 절대 
            # insertAdjacentHTML(...)
            r'(?<![\w$])(?:[A-Za-z_$][\w$]*|\))\s*(?:\.\s*insertAdjacentHTML|\[\s*["\']insertAdjacentHTML["\']\s*\])\s*\(',

        ]

        self.strong_pattern = [(p, re.compile(p, re.IGNORECASE | re.DOTALL)) for p in strong_patterns_raw]
        self.weak_pattern   = [(p, re.compile(p, re.IGNORECASE | re.DOTALL)) for p in weak_patterns_raw]

        self.NETWORK_NEAR_SENSITIVE = re.compile(
            r'(?:fetch|sendBeacon)\s*\(\s*["\']https?://|\.open\s*\(\s*["\'](?:GET|POST)["\']\s*,\s*["\']https?://',
            re.IGNORECASE
        )

    def cleanup(self):
        for f in (self.result_txt_path, self.result_json_path):
            try:
                if os.path.exists(f):
                    os.remove(f)
                    print(f"{f} 파일 삭제 완료 ")
            except Exception:
                pass

    def openfile(self):
        if os.path.isfile(self.combined_path):
            with open(self.combined_path, 'r', encoding='utf-8', errors='ignore') as f:
                self.content = f.read()

    def _near_sensitive(self, text, s, e):
        a = max(0, s - self.WINDOW)
        b = min(len(text), e + self.WINDOW)
        return bool(self.SENSITIVE_RE.search(text[a:b]))

    def combined_detector(self):
        if not self.content:
            self.result = {}
            return

        text = self.content
        strong_hits = []
        weak_hits = []
        strong_count = 0
        weak_count = 0

        for pat, rgx in self.strong_pattern:
            matches = list(rgx.finditer(text))
            if matches:
                strong_count += 1
                strong_hits.append({"pattern": pat, "count": len(matches)})

        for pat, rgx in self.weak_pattern:
            matches = list(rgx.finditer(text))
            if matches:
                weak_count += 1
                weak_hits.append({"pattern": pat, "count": len(matches)})

        combo_hits = 0
        for m in self.NETWORK_NEAR_SENSITIVE.finditer(text):
            if self._near_sensitive(text, m.start(), m.end()):
                combo_hits += 1
                break
        if combo_hits > 0:
            strong_hits.append({"pattern": "NETWORK_NEAR_SENSITIVE", "count": combo_hits})
            strong_count += 1

        # 등급별 이모지 & 설명
        if strong_count >= 1:
            verdict = "high"
            summary = "🔴 고위험 - 강한 피싱 시그니처 발견"
            score = 80
        elif weak_count >= 3:
            verdict = "medium"
            summary = "🟠 중위험 - 약한 피싱 신호 다수"
            score = 45
        elif weak_count >= 1:
            verdict = "low"
            summary = "🟡 저위험 - 일부 의심 신호"
            score = 20
        else:
            verdict = "none"
            summary = "🟢 안전 - 의심 없음"
            score = 0

        self.result = {
            "score": score,
            "label": verdict,
            "summary": summary,
            "strong_count": strong_count,
            "weak_count": weak_count,
            "strong_hits": strong_hits,
            "weak_hits": weak_hits
        }

    def makefile(self):
        if not self.result:
            return
        os.makedirs(os.path.dirname(self.result_txt_path), exist_ok=True)

        with open(self.result_txt_path, 'w', encoding='utf-8') as f:
            f.write(json.dumps(self.result, ensure_ascii=False, indent=2))
        with open(self.result_json_path, 'w', encoding='utf-8') as f:
            json.dump(self.result, f, ensure_ascii=False, indent=2)

    def run(self):
        """ 전체 실행 """
        self.cleanup()
        self.openfile()
        self.combined_detector()
        self.makefile()
        return self.result
