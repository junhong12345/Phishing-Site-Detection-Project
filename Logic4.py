#logic4 모듈화 version
#resource type, status 두 파트 새로 추가함 

import os, json, sys

class Network_Detector:
    def __init__(self,
                 network_path="/root/project/network_log.json",
                 result_path="/root/project/logic4_Detector_result.json"):
        self.network_path = network_path
        self.result_path = result_path
        self.records = []
        self.result = []
        self.result1 = []  # detector1 결과
        self.result2 = []  # detector2 결과

    def cleanup_result(self):
        if os.path.exists(self.result_path):
            try:
                os.remove(self.result_path)
                print(f"[CLEAN] removed: {self.result_path}")
            except Exception as e:
                print(f"[WARN] cleanup failed: {e}")

    def load_network_log(self):
        if not os.path.isfile(self.network_path):
            print(f"[ERR] not found: {self.network_path}")
            sys.exit(1)
        try:
            with open(self.network_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            print(f"[ERR] JSON decode failed: {e}")
            sys.exit(1)

        if isinstance(data, dict) and "logs" in data:
            data = data["logs"]
        if not isinstance(data, list):
            print("[ERR] network_log.json should be a list of objects")
            sys.exit(1)

        self.records = data
        print(f"[OK] loaded {len(self.records)} records")

    def combined(self):
        out = []
        for rec in self.records:
            if not isinstance(rec, dict):
                continue
            ts     = rec.get("ts") or rec.get("timestamp")
            method = rec.get("method")
            origin = rec.get("origin")
            host   = rec.get("host") or rec.get("authority")
            url    = rec.get("url") or rec.get("uri")
            status = rec.get("status")
            rtype = rec.get("resource_type") or "other"
            if ts is None and method is None and url is None:
                continue
            out.append({"ts": ts, "method": method, "origin": origin, "host": host, "url": url, "status": status, "resource_type": rtype})
        self.result = out
        print(f"[OK] extracted {len(self.result)} rows")

    def detector1(self):
        ALLOW_HOSTS = {
            # 기존 구글/클라우드플레어
            "ajax.googleapis.com", "fonts.gstatic.com", "fonts.googleapis.com",
            "cdnjs.cloudflare.com", "cdn.jsdelivr.net", "unpkg.com",
            "code.jquery.com", "static.cloudflareinsights.com",
            "www.googletagmanager.com", "www.google-analytics.com",

            # ✅ 네이버 계열 (정상 CDN/리소스 서버)
            "s.pstatic.net", "ssl.pstatic.net", "ntm.pstatic.net",
            "pm.pstatic.net", "phinf.pstatic.net", "naverpa-phinf.pstatic.net",
            "siape.veta.naver.com", "shopsquare.naver.com"
            
        }
        ALLOW_SUFFIXES = {
            ".cloudflareinsights.com", ".cloudflare.com",
            ".pstatic.net",     # ✅ 네이버 CDN 전체 허용
            ".naver.com"        # ✅ 네이버 도메인 전체 허용
        }

        def _etld1(h: str) -> str:
            if not h: return ""
            parts = h.lower().split(".")
            return ".".join(parts[-2:]) if len(parts) >= 2 else h.lower()

        def _tld(h: str) -> str:
            if not h: return ""
            return h.lower().split(".")[-1]

        for rec in self.result:
            origin = (rec.get("origin") or "").lower().strip()
            host   = (rec.get("host") or rec.get("authority") or "").lower().strip()

            score = 0
            cross = False

            if not origin or not host:
                rec["cross_origin"] = None
                rec["cross_score"] = 0
                rec["cross_risk"] = "low"
                continue

            if host in ALLOW_HOSTS or any(host.endswith(suf) for suf in ALLOW_SUFFIXES):
                rec["cross_origin"] = False
                rec["cross_score"] = 0
                rec["cross_risk"] = "low"
                continue

            if _etld1(origin) != _etld1(host):
                cross = True
                score += 2
                if _tld(origin) != _tld(host):
                    score += 1

            risk = "low"
            if score >= 3: risk = "medium"
            if score >= 5: risk = "high"

            rec["cross_origin"] = cross
            rec["cross_score"] = score
            rec["cross_risk"] = risk

            if cross:
                print(f"[SUSPECT] origin({origin}) != host({host}) | score={score} risk={risk}")
                self.result1.append(rec)

    def detector2(self):
        import re
        from urllib.parse import urlparse, parse_qsl

        SUS_PATH = re.compile(r'/(login|signin|verify|account|secure|auth|update|billing|reset|recovery|2fa|otp|mfa|submit|send|gate)\b', re.I)
        EXFIL_HINT = re.compile(r'(telegram|discord\.com/api/webhooks|webhook|formspree|sendgrid|mailgun|api\.email|pastebin|ipfs|telegra\.ph)', re.I)
        SUS_PARAM = re.compile(r'(pass(word)?|pwd|token|api[_-]?key|secret|session|sid|csrf|otp|code|pin|mnemonic|seed|private(key)?|wallet|mail|email|phone|card|cvv)', re.I)
        SHORTENERS = {'bit.ly', 't.co', 'tinyurl.com', 'goo.gl', 'is.gd', 'ow.ly', 'cutt.ly', 'bitly.com'}

        for rec in self.result:
            url = rec.get('url') or ''
            method = (rec.get('method') or '').upper()

            if not url or not method:
                rec['url_method_score'] = 0
                rec['url_method_risk'] = 'low'
                continue

            p = urlparse(url)
            path = p.path or ''
            host = (p.hostname or '').lower()
            ev_score = 0

            if SUS_PATH.search(path):
                ev_score += 2

            qs = parse_qsl(p.query, keep_blank_values=True)
            if method == 'GET':
                if any(SUS_PARAM.search(k) or SUS_PARAM.search(str(v)) for k, v in qs):
                    ev_score += 3
                if any(len(v) > 200 and re.fullmatch(r'[A-Za-z0-9+/=]+', v or '') for _, v in qs):
                    ev_score += 2

            if method in {'POST', 'PUT', 'PATCH'}:
                if path.lower().endswith(('.png', '.jpg', '.jpeg', '.svg', '.gif', '.css', '.js')):
                    ev_score += 3
                if SUS_PATH.search(path):
                    ev_score += 2

            if EXFIL_HINT.search(url):
                ev_score += 3

            if re.fullmatch(r'\d{1,3}(\.\d{1,3}){3}', host):
                ev_score += 1

            if host in SHORTENERS:
                ev_score += 1

            risk = 'low'
            if ev_score >= 6: risk = 'high'
            elif ev_score >= 3: risk = 'medium'

            rec['url_method_score'] = ev_score
            rec['url_method_risk'] = risk

            if ev_score > 0:
                print(f"[URL/METHOD SUSPECT] {method} {url} | score={ev_score} risk={risk}")
                self.result2.append(rec)

    def save_result(self):
        try:
            merged = []
            seen = set()

            def _key(r):
                return (r.get("ts"), r.get("method"), r.get("url"))

            def _combine_risk(a, b):
                rank = {"low": 1, "medium": 2, "high": 3}
                ra = rank.get(a or "low", 1)
                rb = rank.get(b or "low", 1)
                for k, v in rank.items():
                    if v == max(ra, rb):
                        return k
                return "low"

            for r in (self.result1 + self.result2):
                k = _key(r)
                if k in seen:
                    continue
                seen.add(k)
                merged.append({
                    "ts": r.get("ts"),
                    "method": r.get("method"),
                    "origin": r.get("origin"),
                    "host": r.get("host") or r.get("authority"),
                    "url": r.get("url") or r.get("uri"),
                    "risk": _combine_risk(r.get("cross_risk"), r.get("url_method_risk")),
                    "flags": {
                        "cross": bool(r.get("cross_origin")),
                        "url_method": bool((r.get("url_method_score") or 0) > 0)
                    },
                    "resource_type": r.get("resource_type") or "other",
                    "status": r.get("status")
                })

            out = {
                "total_records": len(self.result),
                "suspect_count": len(merged),
                "suspects": merged
            }
            with open(self.result_path, "w", encoding="utf-8") as f:
                json.dump(out, f, ensure_ascii=False, indent=2)

            print(f"[DONE] saved -> {self.result_path}")
            return out
        except Exception as e:
            print(f"[ERR] save_result failed: {e}")
            return None

    def run(self):
        """ 전체 실행 """
        self.cleanup_result()
        self.load_network_log()
        self.combined()
        self.detector1()
        self.detector2()
        return self.save_result()
