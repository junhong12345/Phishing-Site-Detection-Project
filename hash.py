import os, hashlib
from datetime import datetime

class Hasher:
    def __init__(self):
        self.total_path = '/root/project'
        self.downloaded_path = os.path.join(self.total_path, "downloaded")
        
    def make_hash(self):
        if os.path.exists(self.downloaded_path):
            for filename in os.listdir(self.downloaded_path):
                if filename == "screenshot.png":
 #                   print("스크린샷 파일 제외 성공")
                    continue
                
                    
                filepath = os.path.join(self.downloaded_path, filename)

                try:
                    # 시간 문자열 (년월일시분초)
                    now_time = datetime.now().strftime("%Y%m%d%H%M%S")

                    # 원래 파일 이름 + 시간 → 해시 입력
                    input_string = filename + now_time
                    hash_object = hashlib.sha256(input_string.encode())
                    hex_dig = hash_object.hexdigest()

                    newpath = os.path.join(self.downloaded_path, hex_dig)

                    os.rename(filepath, newpath)
#                    print(f"{filename} + {now_time} -> {hex_dig} 변환 성공")

                except Exception as e:
                    print(f"ERROR renaming {filename}: {e}")
