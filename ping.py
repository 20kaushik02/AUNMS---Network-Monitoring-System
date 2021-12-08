import sys
from PyQt5.QtGui     import *
from PyQt5.QtCore    import *
from PyQt5.QtWidgets import *
from scapy.all import *

class Ping(QWidget):
    def __init__(self):
        super().__init__()
        
        
        self.hostn = QLabel("Enter Address/Hostname to ping:")
        self.host = QLineEdit()
        
        self.startPingBtn = QPushButton()
        self.startPingBtn.setText('Ping')
        self.startPingBtn.clicked.connect(self.startPing)
        
        self.result = QTextEdit()
        self.layoutPing = QVBoxLayout(self)
        self.layoutPing.addWidget(self.hostn)
        self.layoutPing.addWidget(self.host)
        self.layoutPing.addWidget(self.startPingBtn)
        self.layoutPing.addWidget(self.result)
        self.setLayout(self.layoutPing)
        
    def startPing():
        pass