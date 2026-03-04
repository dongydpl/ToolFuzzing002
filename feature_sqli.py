import requests
import time
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urljoin
from PyQt6.QtCore import QThread, pyqtSignal

class SQLiThread(QThread):
    # Các tín hiệu (Signals) để gửi dữ liệu về giao diện chính
    ket_qua_scan = pyqtSignal(str, str, str) # URL, Payload, Loại lỗi tìm thấy
    log_process = pyqtSignal(str)            # Gửi tin nhắn log hiển thị lên màn hình
    hoan_thanh = pyqtSignal()                # Báo cáo khi quét xong toàn bộ
    
    def __init__(self, list_urls):
        super().__init__()
        self.targets = list_urls
        self.is_running = True

        # Payload Error base
        self.error_payloads = ["'", "\"", "')"]

        # Payload Boolean-based
        self.boolean_payloads = [
            (" AND 1=1", " AND 1=2"),
            ("' AND '1'='1", "' AND '1'='2")
        ]
        
        # Payload Time-based - MySQL
        self.time_payloads = [
            " AND SLEEP(3)-- -",
            "' AND SLEEP(3)-- -"
        ]

        # CÁC DẤU HIỆU LỖI DATABASE
        self.sql_errors = [
            "SQL syntax", "mysql_fetch_array", "Warning: mysql",
            "PostgreSQL query failed", "Oracle error", "Unclosed quotation mark"
        ]

    def run(self):
        self.log_process.emit(f"<b>Bắt đầu Fuzzing SQLi trên {len(self.targets)} mục tiêu...</b>")

        for url in self.targets:
            if not self.is_running: break
            #Fuzzing Get (URL có tham số)
            if "?" in url: 
                self.fuzzing_get_params(url)
            #Fuzzing Post (URL ko có tham số nhưng có form điền)
            else:
                self.fuzzing_post_forms(url)

        self.log_process.emit("<b>Hoàn tất toàn bộ quá trình quét!</b>")
        self.hoan_thanh.emit()
    
    # Phương thức để chèn payload
    def build_url_get(self,origin_url,params,target_param,payload):
        param_have_payload = []
        for name_param,value_param in params.items():# Dùng .items() để qly key:value của direction dễ hơn
            if name_param == target_param:
                param_have_payload.append(f"{name_param}={value_param[0]}{payload}")  
            else:
                param_have_payload.append(f"{name_param}={value_param[0]}")
        return f"{origin_url}?{'&'.join(param_have_payload)}"

    def send_post_have_payload(self, post_url, data, payload, field, original_url):
        try:
            response = requests.post(post_url, data = data, timeout = 5)

            for error in self.sql_errors:
                if error.lower() in response.text.lower():
                    self.ket_qua_scan.emit(original_url, f"Ô: {field} | Payload: {payload}", f"POST SQLi ({error})")
                    self.log_process.emit(f"<b style='color:red'>[!] PHÁT HIỆN SQLi POST tại Form: {original_url} (Ô: {field})</b>")
                    break
        except Exception:
            pass

    def fuzzing_get_params(self,url):
        parsed = urlparse(url) #
        params = parse_qs(parsed.query) #...?id=1&user=admin => Dicionary(key:value) {'id': ['123'], 'category': ['book']}.
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for param_name in params: #loop1: id , loop2: user
            if not self.is_running: break
            self.log_process.emit(f"[*] Đang quét tham số: <i style='color:green'>{param_name}</i>")

            #Error base
            for payload in self.error_payloads:
                new_url = self.build_url_get(base_url,params,param_name,payload)
                try:
                    #Gửi request
                    response = requests.get(new_url,timeout=5)
                    #check xem có lỗi trong response không ?
                    for error in self.sql_errors:
                        if error.lower() in response.text.lower():
                            # Gửi kết quả về tableWidget ở file Main
                            self.ket_qua_scan.emit(url,payload,f"Error-based: {error}")
                            self.log_process.emit(f"<b style='color:red'>[!] Phát hiện Error-based tại tham số: {param_name} trên url: {url}</b>")
                            break
                except: pass

            #Boolean-based
            for payload_true,payload_false in  self.boolean_payloads:
                new_url_true = self.build_url_get(base_url,params,param_name,payload_true)
                new_url_false = self.build_url_get(base_url,params,param_name,payload_false)
                try:
                    response_true = requests.get(new_url_true,timeout=5)
                    response_false = requests.get(new_url_false, timeout=5)
                    if len(response_true.text) != len(response_false.text):
                        self.ket_qua_scan.emit(url,payload_true,"Boolean-based")
                        self.log_process.emit(f"<b style='color:red'>[!] Phát hiện Boolean-base tại tham số: {param_name} trên url: {url}</b>")
                except: pass

            #Time-based
            for payload_time in self.time_payloads:
                new_url_time = self.build_url_get(base_url,params,param_name,payload_time)
                start = time.time() #lấy thời gian hiện tại (s) ngay trước khi gửi request
                try:
                    response_time = requests.get(new_url_time, timeout = 10)
                    if time.time() - start >= 3:
                        self.ket_qua_scan.emit(url, payload_time, "Time-based")
                        self.log_process.emit(f"<b style='color:red'>[!] Phát hiện Time-based tại tham số: {param_name} trên url: {url}</b>")
                except: pass

    def fuzzing_post_forms(self,url):
        try:
            response = requests.get(url, timeout = 5)
            soup = BeautifulSoup(response.text, 'html.parser')
            # 2. Tìm tất cả các thẻ <form> trên trang
            forms = soup.find_all('form')
            if not forms: return
            self.log_process.emit(f"[*] Tìm thấy {len(forms)} Form tại: {url}. Đang trích xuất dữ liệu...")

            for form in forms:
                if not self.is_running: break

                # Tìm thuộc tính action trên thẻ form
                action = form.get('action')
                #Tìm tiếp thuộc tính method
                method = form.get('method','get').lower()

                if method == 'post':
                    target_url = urljoin(url, action)
                    # Tìm thẻ input ( xem form có những ô nhập liệu nào)
                    inputs = form.find_all(['input', 'textarea'])
                    body_post = {} #Dictionary key:value body chứa dữ liệu gửi lên server
                    list_fields = [] # List chứa các trường (fields) có thể nhập liệu

                    for tag in inputs:
                        name = tag.get('name') # Lấy thuộc tính name của thẻ (vì trong HTML, khi gửi form thì server sẽ lấy dữ liệu dựa trên thuộc tính name)
                        if not name: continue # Bỏ qua input không có tên

                        value = tag.get('value','') # Lấy giá trị  mặc định trong thuộc tính value. nếu ko có để trông ''
                        type_input = tag.get('type', 'text').lower() # Lấy type của ô input, nếu không ghi rỗ mặc định là text
                        body_post[name] = value

                        # Chỉ Fuzz những ô nhập liệu văn bản ( tránh fuzz type="submit" or "checkbox" ....)
                        if type_input in ['text', 'password', 'textarea', 'email', 'search']:
                            list_fields.append(name)

                    # 4. Bắt đầu bơm Payload vào từng field một
                    for field in list_fields:
                        for payload in self.error_payloads:
                            if not self.is_running: return
                            
                            # Tạo bản sao dữ liệu và chèn payload vào ô mục tiêu
                            untrusted_data = body_post.copy()
                            untrusted_data[field] = f"{body_post[field]}{payload}"
                            self.send_post_have_payload(target_url, untrusted_data, payload, field, url)
        except Exception:
            pass

    def stop(self):
        self.is_running = False