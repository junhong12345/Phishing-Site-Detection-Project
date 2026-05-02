

#삭제 프로그램
import os, re, sys, time, json, shutil

def delete_file():
    total_path = "/root/project"
    logic1_path =  os.path.join(total_path, "Domain_result.txt")
    logic3_path = os.path.join(total_path, "JS_Detector_result.txt")
    logic3_json_path = os.path.join(total_path, "JS_Detector_result.json")
    logic4_path =  os.path.join(total_path, "logic4_Detector_result.json")
    network_log_path =  os.path.join(total_path, "network_log.json")
    final_reuslt_txt_path =  os.path.join(total_path, "final_score.json")
    final_result_json_path =  os.path.join(total_path, "final_result.json")
    gpt_reult_json_path = os.path.join(total_path, "gpt_result.json")
    gpt_result_score_path = os.path.join(total_path, "gpt_result_score.json")
    downloaded_path =  os.path.join(total_path,  "downloaded")

    try:
        for a in (logic1_path, logic3_path, logic3_json_path, logic4_path, network_log_path, final_result_json_path, final_reuslt_txt_path, gpt_reult_json_path, gpt_result_score_path):
            if not os.path.exists(a):
                print(f"{a} 파일이 존재하지 않습니다.")
            elif os.path.exists(a) and os.path.isfile(a):
                os.remove(a)
                print(f"{a}파일 삭제 완료")
    except Exception as e:
        print(f"ERROR: {e}")

    try:
        if not os.path.exists(downloaded_path):
            print(f"{downloaded_path}파일이 존재하지 않습니다.")
        elif os.path.exists(downloaded_path) and os.path.isdir(downloaded_path):
            shutil.rmtree(downloaded_path)
            print(f"{downloaded_path}파일 삭제 완료 ")

    except Exception as e:
        print(f"ERROR: {e}")

if __name__=="__main__":
    delete_file()


