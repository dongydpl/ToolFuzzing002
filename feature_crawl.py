import requests
from collections import deque
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from PyQt6.QtCore import QThread, pyqtSignal

class CrawlerThread(QThread):
    tin_nhan = pyqtSignal(str)
    tim_thay_link_co_tham_so = pyqtSignal(str)
    tim_thay_link_full = pyqtSignal(str)
    hoan_thanh = pyqtSignal()

    def __init__(self, start_url: str, max_depth: int):
        super().__init__()
        self.start_url = start_url
        self.max_depth = max_depth
        self.is_running = True

    def run(self):
        target = self.start_url
        if not target.startswith("http"):
            target = "http://" + target

        queue = deque([(target, 0)])
        visited = set([target])

        self.tin_nhan.emit(f"🚀 Bắt đầu quét: {target}")

        while queue and self.is_running:
            url, depth = queue.popleft()

            if depth > self.max_depth:
                continue

            self.tin_nhan.emit(f"[*] Đang quét (Depth {depth}): {url}")

            try:
                res = requests.get(url, timeout=5)

                if res.status_code != 200:
                    continue

                # 1. Kiểm tra URL hiện tại xem có tham số sẵn không
                parsed = urlparse(url)
                if parsed.query:
                    self.tin_nhan.emit(f"<b style='color:blue;'>[+] MỤC TIÊU CÓ THAM SỐ: {url}</b>")
                    self.tim_thay_link_co_tham_so.emit(url)

                if depth < self.max_depth:
                    soup = BeautifulSoup(res.text, "html.parser")

                    # ==========================================
                    # BỘ LỌC 1: TÌM KIẾM CÁC THẺ <FORM> (NÂNG CẤP)
                    # ==========================================
                    for form in soup.find_all("form"):
                        method = form.get("method", "GET").upper()
                        action = form.get("action", "")
                        form_url = urljoin(url, action)
                        
                        # Xử lý các form GET để tạo URL chứa tham số giả lập
                        if method == "GET":
                            inputs = form.find_all(["input", "select", "textarea"])
                            params = []
                            for inp in inputs:
                                name = inp.get("name")
                                # Bỏ qua các nút bấm không chứa dữ liệu
                                if name and inp.get('type') not in ['submit', 'button', 'image', 'reset']:
                                    params.append(f"{name}=FUZZ_TEST")
                            
                            # Nếu form có ô nhập liệu (như ô search), ghép lại thành link
                            if params:
                                query_string = "&".join(params)
                                full_param_url = f"{form_url}?{query_string}"
                                
                                self.tin_nhan.emit(f"<b style='color:purple;'>[+] PHÁT HIỆN FORM GET: {full_param_url}</b>")
                                # Đưa link giả lập này vào danh sách để XSS/LFI/SQLi tấn công
                                self.tim_thay_link_co_tham_so.emit(full_param_url)
                                
                        # Đưa URL gốc của form vào danh sách full để XSS thread quét sâu hơn
                        if form_url not in visited:
                            self.tim_thay_link_full.emit(form_url)
                            visited.add(form_url)

                    # ==========================================
                    # BỘ LỌC 2: TÌM KIẾM CÁC THẺ <A> ĐỂ ĐI TIẾP
                    # ==========================================
                    for tag in soup.find_all("a"):
                        href = tag.get("href")
                        if not href: continue
                        
                        full_url = urljoin(url, href)

                        # Chỉ quét các link nằm trong cùng tên miền (domain)
                        if urlparse(full_url).netloc == urlparse(target).netloc:
                            if full_url not in visited:
                                self.tim_thay_link_full.emit(full_url)
                                visited.add(full_url)
                                queue.append((full_url, depth + 1))

            except Exception:
                pass

        self.tin_nhan.emit("<b>🏁 --- ĐÃ CRAWL XONG ---</b>")
        self.hoan_thanh.emit()

    def stop(self):
        self.is_running = False