#Result.py
#GPT scanner 포함해서 하는 버전 

import os
import json

class Result:
    def __init__(self):
        self.final_result = {}
        self.final_score = {}
        self.final_result_path = '/root/project/final_result.json'
        self.requests = ''
        self.gpt_result_path = "/root/project/gpt_result_score.json"
        self.gpt_result = {}

    def openfile(self):
        try:
            if os.path.exists(self.final_result_path) and os.path.isfile(self.final_result_path):
                with open(self.final_result_path, 'r', encoding='utf-8') as f:
                    self.final_result = json.load(f)
                    print(f"{self.final_result_path} 파일 불러오기 성공")
            if os.path.exists(self.gpt_result_path) and os.path.isfile(self.gpt_result_path):
                with open(self.gpt_result_path, "r", encoding="utf-8") as f:
                    self.gpt_result = json.load(f)
        except Exception as e:
            print(f"ERROR: {e}")
    

    def make_result_file(self):
        try:
            score = 0.0
            logic_scores = {"logic1_2": 0, "logic3": 0, "logic4": 0}
            weight = 1.0  # 기본값

            # Logic1+2 점수
            logic1_2_result = self.final_result.get("logic1_2", {})

            if isinstance(logic1_2_result, list) and logic1_2_result:
                logic_scores["logic1_2"] = 130
                score += 130
                weight = 1.0

            elif isinstance(logic1_2_result, dict) and logic1_2_result.get("ssim_percentage") is not None:
                ssim = logic1_2_result.get("ssim_percentage", 100)
                if ssim < 60:
                    logic_scores["logic1_2"] = 70
                    weight = 1.0
                elif ssim < 80:
                    logic_scores["logic1_2"] = 20
                    weight = 0.5
                else:
                    logic_scores["logic1_2"] = 0
                    weight = 0.0
                score += logic_scores["logic1_2"]

            else:
                logic_scores["logic1_2"] = 0
                weight = 1.5

            print(f"Logic1+2 점수: {logic_scores['logic1_2']}")

            # GPT_scanner 점수 
            #gpt_score = 0
            #if isinstance(self.gpt_result, dict):
            #    gpt_score = sum(chunk.get("risk_score", 0) for chunk in self.gpt_result.values())
            #score += gpt_score
            #print(f"GPT Scanner 원점수 : {gpt_score}")

            # GPT_scanner 점수 
            # 걸린 것들 중에서 평균 값 추출     
            gpt_score = 0
            if isinstance(self.gpt_result, dict):
                gpt_scores = [chunk.get("risk_score", 0) for chunk in self.gpt_result.values()]
                gpt_score = sum(gpt_scores) / len(gpt_scores) if gpt_scores else 0
            print(f"GPT Scanner 평균점수 : {gpt_score}")
            
            

            # Logic3 점수
            logic3_result = self.final_result.get("logic3", {})
            logic_scores["logic3"] = logic3_result.get("score", 0)
            print(f"Logic3 원점수: {logic_scores['logic3']}")

            # Logic4 점수
            logic4_result = self.final_result.get("logic4", {})
            suspects = logic4_result.get("suspect_count", 0)
            if suspects >= 10:
                logic_scores["logic4"] = 50
            elif suspects >= 5:
                logic_scores["logic4"] = 30
            elif suspects >= 1:
                logic_scores["logic4"] = 15
            print(f"Logic4 원점수: {logic_scores['logic4']}")

            # 가중치 반영
            logic3_weighted = logic_scores["logic3"] * weight
            logic4_weighted = logic_scores["logic4"] * weight
            gpt_weighted = gpt_score * weight
            score += logic3_weighted + logic4_weighted + gpt_weighted

            print(f"[가중치] GPT_Scanner * {weight} = {gpt_weighted}")
            print(f"[가중치] Logic3 * {weight} = {logic3_weighted}")
            print(f"[가중치] Logic4 * {weight} = {logic4_weighted}")

            # 최종 판정
            if score >= 130:
                verdict = "🔴 고위험"
            elif score >=80:
                verdict = "🟠 중위험"
            elif score >= 1:
                verdict = "🟡 저위험"
            elif score == 0:
                verdict = "🟢 안전"

            if 1<=score<150 and logic_scores["logic4"] ==0 :
                print("해당 사이트의 위험 네트워크 동작이 존재하지 않습니다.")
                self.requests = "해당 사이트의 위험 네트워크 동작이 존재하지 않습니다."
                


            print(f"총점: {score:.1f} | 판정: {verdict}")

            self.final_score["final_score"] = {"score": score, "verdict": verdict}
            self.final_score["final_network_response"] = {"response": self.requests}

        except Exception as e:
            print(f"[점수제 ERROR] {e}")
    

    def make_result(self):
        try:
            with open("final_score.json", "w", encoding='utf-8') as f:
                json.dump(self.final_score, f, ensure_ascii=False, indent=2)
                print("[완료] final_score.json 파일 저장 완료")
        except Exception as e:
            print(f"ERROR: {e}")


