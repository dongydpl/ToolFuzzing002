import requests
from urllib.parse import urlparse, parse_qs, urljoin
from bs4 import BeautifulSoup
from PyQt6.QtCore import QThread, pyqtSignal

class XSSThread(QThread):
    ket_qua_scan = pyqtSignal(str, str, str)
    log_process = pyqtSignal(str)
    hoan_thanh = pyqtSignal()

    def __init__(self, list_urls):
        super().__init__()
        self.targets = list_urls
        self.is_running = True
        self.payloads = [
            '"><script>alert("ToolFuzz_XSS")</script>',
            '<script>alert("ToolFuzz_XSS")</script>',
            '<img src=x onerror=alert("ToolFuzz_XSS")>',
            '<svg/onload=alert("ToolFuzz_XSS")>',
            '<details open ontoggle=alert("ToolFuzz_XSS")>'
        ]
        self.headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ToolFuzz'}
        self.seen_gets = set()
        self.seen_forms = set()

    def is_executable_context(self, html, payload):
        """Bộ lọc thông minh: Phân biệt XSS thật và Ảnh vỡ"""
        soup = BeautifulSoup(html, 'html.parser')
        for tag in soup.find_all(True):
        
            if tag.string and payload in tag.string:
                return True
            
           
            for attr, value in tag.attrs.items():
                if isinstance(value, str) and payload in value:
                    
                    if attr.startswith('on'):
                        return True
                    if attr in ['src', 'href', 'data', 'action', 'formaction']:
                        if '"><' in payload or "'><" in payload:
                            return True
                        return False 
        return True 

    def run(self):
        self.log_process.emit("<b style='color:orange'>🔥 BẮT ĐẦU CÀN QUÉT VỚI BỘ LỌC NGỮ CẢNH...</b>")
        
        for url in self.targets:
            if not self.is_running: break
            self.log_process.emit(f"<hr><b>[*] Đang xử lý:</b> {url}")

            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            if params:
                for param_name in params:
                    sig = f"{base_url}|{param_name}"
                    if sig in self.seen_gets: continue
                    self.seen_gets.add(sig)
                    
                    for payload in self.payloads:
                        if not self.is_running: break
                        test_params = {k: (payload if k == param_name else v[0]) for k, v in params.items()}
                        try:
                            res = requests.get(base_url, params=test_params, headers=self.headers, timeout=5, allow_redirects=True)
                            if payload in res.text and self.is_executable_context(res.text, payload):
                                self.ket_qua_scan.emit(url, payload, f"LỖI XSS (GET: {param_name})")
                                self.log_process.emit(f"<b style='color:red'>[🔥] BINGO! XSS THẬT TẠI GET '{param_name}'!</b>")
                                break 
                        except: pass

            try:
                res = requests.get(url, headers=self.headers, timeout=5)
                soup = BeautifulSoup(res.text, 'html.parser')
                
                for form in soup.find_all('form'):
                    if not self.is_running: break
                    action = form.get('action', '')
                    method = form.get('method', 'get').upper()
                    form_url = urljoin(url, action)
                    
                    inputs = form.find_all(['input', 'textarea', 'select'])
                    param_names = sorted([inp.get('name') for inp in inputs if inp.get('name') and inp.get('type') not in ['submit', 'button', 'image', 'reset', 'hidden']])
                    if not param_names: continue
                    
                    form_id = f"{method}|{form_url}|{str(param_names)}"
                    if form_id in self.seen_forms: continue
                    self.seen_forms.add(form_id)
                    
                    self.log_process.emit(f"<b style='color:purple'>[!] PHÁT HIỆN FORM: {form_url}</b>")

                    for param_name in param_names:
                        for payload in self.payloads:
                            if not self.is_running: break
                            test_data = {p: "fuzz_test" for p in param_names}
                            test_data[param_name] = payload 
                            
                            try:
                                if method == 'POST':
                                    res = requests.post(form_url, data=test_data, headers=self.headers, timeout=5, allow_redirects=True)
                                else:
                                    res = requests.get(form_url, params=test_data, headers=self.headers, timeout=5, allow_redirects=True)

                                if payload in res.text and self.is_executable_context(res.text, payload):
                                    self.ket_qua_scan.emit(form_url, payload, f"XSS (FORM {method}: {param_name})")
                                    self.log_process.emit(f"<b style='color:red; background:yellow'>[🔥] BINGO! XSS THẬT TẠI FORM '{param_name}'!</b>")
                                    break
                            except: pass
            except: pass

        self.log_process.emit("<b>🏁 HOÀN TẤT CÀN QUÉT!</b>")
        self.hoan_thanh.emit()

    def stop(self):
        self.is_running = False