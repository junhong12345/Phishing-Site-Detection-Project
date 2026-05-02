# /root/project/app/main.py
import os, re, json, asyncio
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, JSONResponse
from starlette.staticfiles import StaticFiles

# ===== 경로/상수 =====
BASE_DIR = Path("/root/project")
PIPELINE = BASE_DIR / "main_pipeline.py"
PYTHON = "python3"

FINAL_RESULT = BASE_DIR / "final_result.json"   # 상세 결과
FINAL_SCORE  = BASE_DIR / "final_score.json"    # 최종 점수 (Result.py 산출)
SHOT_FILE    = BASE_DIR / "downloaded" / "screenshot.png"
DOWNLOADED_DIR = BASE_DIR / "downloaded"

IDLE_TIMEOUT = 150  # stdout 무응답 타임아웃(초)

app = FastAPI(title="Detection Backend")

# ===== CORS =====
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"]
)

# ===== 정적 파일 (스크린샷) =====
os.makedirs(DOWNLOADED_DIR, exist_ok=True)
app.mount("/downloaded", StaticFiles(directory=str(DOWNLOADED_DIR)), name="downloaded")

# ===== 헬스체크 =====
@app.get("/", response_class=PlainTextResponse)
async def root():
    return "OK"

@app.get("/healthz", response_class=PlainTextResponse)
async def healthz():
    return "ok"

# ===== 유틸 =====
SCORE_RE   = re.compile(r"Score\s*=\s*([0-9]+(?:\.[0-9]+)?)", re.IGNORECASE)
VERDICT_RE = re.compile(r"Verdict\s*=\s*(.+)$", re.IGNORECASE)

def classify(score: Optional[float]) -> str:
    if score is None: return "🟠 중위험"
    s = float(score)
    if s >= 130: return "🔴 고위험"
    if s >= 80:  return "🟠 중위험"
    if s >= 1:   return "🟡 저위험"
    return "🟢 안전"

def read_json(path: Path) -> Dict[str, Any]:
    if not path.exists(): return {}
    try:
        with path.open("r", encoding="utf-8") as f:
            obj = json.load(f)
            return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}

# ===== WebSocket: 로그 스트리밍 =====
async def run_pipeline_and_stream(url: str, ws: WebSocket) -> Tuple[int, Optional[float], str]:
    env = os.environ.copy()
    proc = await asyncio.create_subprocess_exec(
        PYTHON, "-u", str(PIPELINE),
        cwd=str(BASE_DIR),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        env=env,
    )
    try:
        assert proc.stdin is not None
        proc.stdin.write((url.strip() + "\n").encode())
        await proc.stdin.drain()
        await ws.send_text("[WS] URL 전달: " + url)
    except Exception as e:
        await ws.send_text(f"[WS] URL 주입 실패: {e}")

    last_activity = asyncio.get_event_loop().time()
    last_score: Optional[float] = None
    last_verdict: str = ""

    async def reader():
        nonlocal last_activity, last_score, last_verdict
        assert proc.stdout is not None
        while True:
            line = await proc.stdout.readline()
            if not line:
                break
            txt = line.decode(errors="ignore").rstrip()
            last_activity = asyncio.get_event_loop().time()

            m1 = SCORE_RE.search(txt)
            if m1:
                try: last_score = float(m1.group(1))
                except: pass
            m2 = VERDICT_RE.search(txt)
            if m2:
                last_verdict = m2.group(1).strip()

            await ws.send_text(txt)

    reader_task = asyncio.create_task(reader())

    while True:
        if reader_task.done():
            break
        await asyncio.sleep(1.0)
        if asyncio.get_event_loop().time() - last_activity > IDLE_TIMEOUT:
            await ws.send_text(f"[WS] {IDLE_TIMEOUT}s 무응답 → 파이프라인 종료")
            try: proc.kill()
            except: pass
            break

    rc = await proc.wait()
    return rc, last_score, last_verdict

@app.websocket("/ws")
async def ws_handler(websocket: WebSocket):
    """ 프론트 → {action:'analyze', url:'...'} JSON """
    await websocket.accept()
    try:
        while True:
            raw = await websocket.receive_text()
            try:
                req = json.loads(raw)
            except Exception:
                await websocket.send_text("[WS] Invalid JSON")
                continue

            if req.get("action") != "analyze":
                await websocket.send_text("[WS] Unsupported action")
                continue

            url = (req.get("url") or "").strip()
            if not url:
                await websocket.send_text("[WS] URL missing")
                continue

            for p in (FINAL_RESULT, FINAL_SCORE):
                if p.exists():
                    try:
                        p.unlink()
                        await websocket.send_text(f"[WS] 기존 {p.name} 삭제")
                    except Exception as e:
                        await websocket.send_text(f"[WS] {p.name} 삭제 실패: {e}")

            await websocket.send_text("[WS] 분석 시작: " + url)
            rc, _, _ = await run_pipeline_and_stream(url, websocket)
            await websocket.send_text(f"[WS] 파이프라인 종료 코드: {rc}")
            await websocket.send_text("[WS] 분석 종료")
    except WebSocketDisconnect:
        return
    except Exception as e:
        try: await websocket.send_text(f"[WS][에러] {e}")
        except Exception: pass

# ===== REST: 결과 조회 =====
@app.get("/get-final")
def get_final():
    """ 최종 결과를 텍스트(JSON string)로 반환 """
    target = FINAL_SCORE if FINAL_SCORE.exists() else FINAL_RESULT
    if not target.exists():
        return PlainTextResponse("[정보] 최종 결과 파일이 없습니다.", status_code=404)
    try:
        data = json.loads(target.read_text(encoding="utf-8", errors="ignore"))
        return PlainTextResponse(json.dumps(data, ensure_ascii=False, indent=2))
    except Exception:
        return PlainTextResponse(target.read_text(encoding="utf-8", errors="ignore"))

@app.get("/get-final.json")
def get_final_json():
    # 항상 final_score.json 우선
    result = read_json(FINAL_SCORE)

    if "final_score" in result:   # ✅ 내부 값만 가져오기
        result = result["final_score"]

    # fallback
    if not result:
        result = read_json(FINAL_RESULT)

    # 점수
    raw_score = result.get("score", 0.0)
    try:
        score = float(raw_score)
    except Exception:
        score = 0.0

    # verdict
    verdict = result.get("verdict", "") or result.get("summary", "")
    for emoji in ["🟢","🟡","🟠","🔴"]:
        verdict = verdict.replace(emoji, "")
    verdict = verdict.strip()
    if not verdict:
        verdict = classify(score)

    # reasons
    reasons = result.get("reasons", [])
    if not isinstance(reasons, list):
        reasons = []

    # 스크린샷
    screenshot_url = None
    if SHOT_FILE.exists():
        screenshot_url = f"http://16.184.31.26:8000/downloaded/screenshot.png"

    return JSONResponse({
        "score": score,
        "verdict": verdict,
        "reasons": reasons,
        "screenshot": screenshot_url
    })


