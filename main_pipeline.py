#dns 해석 불가 url에 대한 main_pipeline 수정본
#urlloader 호출 부분에 sys.exit(1) 추가함 
#logic1, logic2 통합 버전 main_pipeline.py
#DB 설정 완료 (sqlite3 사용)
#gpt scanner 포함해서 하는 버전

import json, os, re, sys
import sqlite3
from UrlLoader import UrlLoader
from Logic1_2 import Domain_and_Capture   # Logic1+2 통합 모듈
from GPTscanner import GPTScanner
from Logic3 import JS_Detector
from Logic4 import Network_Detector
from Result import Result
from hash import Hasher #해시함수 

def delete_file():
    final_result_path = '/root/project/final_result.json'
    final_score_path = '/root/project/final_score.json'
    for f in (final_result_path , final_score_path):
        try:
            if os.path.exists(f):
                os.remove(f)
                #print('기존 결과 파일 삭제 완료')
            
                if not os.path.isfile(final_result_path):
                    print(f"{final_result_path} 파일 삭제 완료")
                elif not os.path.isfile(final_score_path):
                    print(f"{final_score_path} 파일 삭제 완료")
    
            
        except Exception as e:
            print(f"ERROR: {e}")


def main():
    url = input("분석할 URL을 입력하세요: ").strip()
    if not url.startswith("http"):      #startswith : 괄호 안의 내용이 문자열에 있냐 없냐 판단 
        url = "https://" + url

    final_result = {}
    final_score = {}

    # -------------------------------
    # 1. URL Loader
    # -------------------------------
    print("\n[1/7] URL Loader 실행 시작")
    try:
        loader = UrlLoader(url)
        loader.download_page_resources()
        loader.extract_javascript()
        loader.scan_steganography()
        final_result["url_loader"] = {
            "save_dir": loader.SAVE_DIR,
            "network_log": loader.OUT_JSON,
            "js_combined": loader.get_combined_path()
        }
        print("[1/7] URL Loader 완료\n")
    except Exception as e:
        #print(f"[1/6] URL Loader ERROR: {e}")
        print("존재하지 않는 사이트입니다.")
        sys.exit(1)
            

    # -------------------------------
    # 2. Logic1+2 (블랙리스트 + 스크린샷)
    # -------------------------------
    print("[2/7] Logic1+2 실행 시작")
    try:
        logic1_2 = Domain_and_Capture(url)
        logic1_2.delete_Domain()
        logic1_2.getUrl()
        logic1_2.check_blacklist()
        logic1_2.makefile()
        result_1_2 = logic1_2.judge()
        final_result["logic1_2"] = result_1_2
        print("[2/7] Logic1+2 완료\n")
    except Exception as e:
        print(f"[2/7] Logic1+2 ERROR: {e}")
    # -------------------------------
    # 3. GPTscanner (AI 분석)
    # -------------------------------
    print("[3/7] GPTscanner - AI 분석 실행 시작")
    try:
        scanner = GPTScanner()
        scanner.delete_file()
        scanner.load_file()
        scanner.analyze_chunks()
        scanner.save_json_results()
        scanner.take_score()
    except Exception as e:
        print(f"[2/7] GPT scanner ERROR: {e}")
    # -------------------------------
    # 3. Logic3 (JS 정적 분석)
    # -------------------------------
    print("[4/7] Logic3 - JS 정적 분석 실행 시작")
    try:
        logic3 = JS_Detector()
        logic3.cleanup()
        logic3.openfile()
        logic3.combined_detector()
        logic3.makefile()
        final_result["logic3"] = logic3.result
        print("[3/6] Logic3 완료\n")
    except Exception as e:
        print(f"[3/6] Logic3 ERROR: {e}")

    # -------------------------------
    # 4. Logic4 (네트워크 로그 분석)
    # -------------------------------
    print("[5/7] Logic4 - 네트워크 로그 분석 실행 시작")
    try:
        network_path = final_result.get("url_loader", {}).get("network_log", "/root/project/network_log.json")
        logic4 = Network_Detector(network_path=network_path)
        logic4.cleanup_result()
        logic4.load_network_log()
        logic4.combined()
        logic4.detector1()
        logic4.detector2()
        logic4.save_result()
        final_result["logic4"] = {
            "total_records": len(logic4.result),
            "suspect_count": len(logic4.result1) + len(logic4.result2)
        }
        print("[5/7] Logic4 완료\n")
    except Exception as e:
        print(f"[5/7] Logic4 ERROR: {e}")
    # -------------------------------
    # 5. 최종 결과 저장
    # -------------------------------
    print("[6/7] 최종 결과 저장")
    try:
        with open("final_result.json", "w", encoding="utf-8") as f:
            json.dump(final_result, f, ensure_ascii=False, indent=2)
        print("[완료] 모든 로직 실행이 끝났습니다. 결과는 final_result.json에 저장되었습니다.")
    except Exception as e:
        print(f"[6/7] 결과 저장 ERROR: {e}")

    # -------------------------------
    # 6. 점수 계산 (가중치 포함)
    # -------------------------------
    print("\n[7/7] 점수제 프로그램 실행")
    try:
        result = Result()
        result.openfile()
        result.make_result_file()


        final_score = result.final_score.get("final_score", {})
        score = final_score.get("score", 0)
        verdict = final_score.get("verdict", "unknown")

        
        with sqlite3.connect("results.db") as conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO detections (url, score, verdict) VALUES (?, ?, ?)",
                (url, score, verdict)
            )
            conn.commit()
            print(f"[DB 저장 완료] URL={url}, Score={score}, Verdict={verdict}")

            result.make_result()

        print("[7/7] Result 완료 \n")
        print("[7/7] 결과 산정 프로그램 완료 \n")
    except Exception as e:
        print(f"[7/7] 결과 저장 ERROR: {e}")

    # -------------------------------
    #  해시 변환
    # -------------------------------
    print("해시 변환 시작")

    try:
        mkhash = Hasher()
        mkhash.make_hash()



    except Exception as e:
        print(f"ERROR: {e}")


if __name__ == "__main__":
    delete_file()
    main()
