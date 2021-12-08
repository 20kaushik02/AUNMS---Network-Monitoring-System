import sys
from PyQt5.QtGui     import *
from PyQt5.QtCore    import *
from PyQt5.QtWidgets import *
from scapy.all import *

class TraceRoute(QWidget):
    def __init__(self):
        super().__init__()
        
        self.hostn = QLabel("Enter Address/Hostname to trace:")
        self.host = QLineEdit()
        
        self.startTraceBtn = QPushButton()
        self.startTraceBtn.setText('Trace Route')
        self.startTraceBtn.clicked.connect(self.startTrace)
        
        self.result = QTextEdit()
        self.layoutTrace = QVBoxLayout(self)
        self.layoutTrace.addWidget(self.hostn)
        self.layoutTrace.addWidget(self.host)
        self.layoutTrace.addWidget(self.startTraceBtn)
        self.layoutTrace.addWidget(self.result)
        self.setLayout(self.layoutTrace)
        
    def startTrace():
        pass