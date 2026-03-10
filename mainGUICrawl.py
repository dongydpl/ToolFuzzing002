import sys
from PyQt6.QtWidgets import QApplication, QMainWindow, QTableWidgetItem, QMessageBox, QHeaderView
from PyQt6.QtCore import Qt


from GUICrawl import Ui_MainWindow      
from feature_crawl import CrawlerThread  
from feature_lfi import LFIThread        
from feature_sqli import SQLiThread  
from feature_xss import XSSThread  

class PhanMemLFI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)

        self.danh_sach_muc_tieu_co_tham_so = []
        self.danh_sach_muc_tieu_full = []

       
        self.ui.tableWidget.setColumnCount(4)
        self.ui.tableWidget.setHorizontalHeaderLabels(["STT", "URL Mục Tiêu", "Payload", "Kết Quả"])
        header = self.ui.tableWidget.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)

       
        self.ui.jBntScan.clicked.connect(self.xu_ly_crawl)
        self.ui.pushButton.clicked.connect(self.xu_ly_lfi)
        self.ui.pushButton.setEnabled(False)
        self.ui.btnSQLi.clicked.connect(self.xu_ly_sqli)
        self.ui.btnXSS.clicked.connect(self.xu_ly_xss)
        self.ui.btnXSS.setEnabled(False) 
        self.ui.btnSQLi.setEnabled(False) 


    def xu_ly_crawl(self):
        
        url = self.ui.txtGetLink.toPlainText().strip()

      
        if not url:
            QMessageBox.warning(self, "Lỗi", "Vui lòng nhập URL!")
            return

        
        if not url.startswith("http"):
            url = "http://" + url
            self.ui.txtGetLink.setPlainText(url)

        
        self.danh_sach_muc_tieu_co_tham_so = []
        self.danh_sach_muc_tieu_full = []
        self.ui.textBrowser.clear()
        self.ui.jBntScan.setEnabled(False)  
        self.ui.jBntScan.setText("Đang chạy...")  

       
        self.crawler = CrawlerThread(url, 3)

      
        self.crawler.tin_nhan.connect(self.ui.textBrowser.append)
        self.crawler.tim_thay_link_co_tham_so.connect(self.luu_link_ngon_co_tham_so)
        self.crawler.tim_thay_link_full.connect(self.luu_link_ngon_full)
        self.crawler.hoan_thanh.connect(self.crawl_xong)

       
        self.crawler.start()

    def luu_link_ngon_co_tham_so(self, url):
        if url not in self.danh_sach_muc_tieu_co_tham_so:
            self.danh_sach_muc_tieu_co_tham_so.append(url)

    def luu_link_ngon_full(self, url):
        if url not in self.danh_sach_muc_tieu_full:
            self.danh_sach_muc_tieu_full.append(url)

    def crawl_xong(self):
        self.ui.jBntScan.setEnabled(True)
        if len(self.danh_sach_muc_tieu_co_tham_so) > 0:
            self.ui.pushButton.setEnabled(True)
            self.ui.btnSQLi.setEnabled(True)
            self.ui.btnXSS.setEnabled(True)
            QMessageBox.information(self, "Thông báo", f"Tìm thấy {len(self.danh_sach_muc_tieu_co_tham_so)} link ngon!\nSẵn sàng tấn công.")
        else:
            QMessageBox.warning(self, "Thông báo", "Không tìm thấy link nào.")

  
    def xu_ly_lfi(self):
        self.ui.tableWidget.setRowCount(0)

       
        self.attacker = LFIThread(self.danh_sach_muc_tieu_co_tham_so)
       
        self.attacker.log_process.connect(self.ui.textBrowser.append)
        self.attacker.ket_qua_scan.connect(self.dien_vao_bang)

        self.attacker.start()

    def dien_vao_bang(self, url, payload, status):
        row = self.ui.tableWidget.rowCount()
        self.ui.tableWidget.insertRow(row)

        self.ui.tableWidget.setItem(row, 0, QTableWidgetItem(str(row + 1)))
        self.ui.tableWidget.setItem(row, 1, QTableWidgetItem(url))
        self.ui.tableWidget.setItem(row, 2, QTableWidgetItem(payload))

        item_status = QTableWidgetItem(status)
        item_status.setForeground(Qt.GlobalColor.red)
        self.ui.tableWidget.setItem(row, 3, item_status)
    
    def xu_ly_sqli(self):
       
        self.attacker_sql = SQLiThread(self.danh_sach_muc_tieu_full)
        self.attacker_sql.log_process.connect(self.ui.textBrowser.append)
        self.attacker_sql.ket_qua_scan.connect(self.dien_vao_bang)
        self.attacker_sql.hoan_thanh.connect(lambda: QMessageBox.information(self, "Xong", "Đã quét xong SQLi!"))
        
        self.attacker_sql.start()
    def xu_ly_xss(self):
        self.attacker_xss = XSSThread(self.danh_sach_muc_tieu_full)
        self.attacker_xss.log_process.connect(self.ui.textBrowser.append)
        self.attacker_xss.ket_qua_scan.connect(self.dien_vao_bang)
        self.attacker_xss.hoan_thanh.connect(lambda: QMessageBox.information(self, "Xong", "Đã quét xong XSS!"))
        
        self.attacker_xss.start()
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PhanMemLFI()
    window.show()
    sys.exit(app.exec())