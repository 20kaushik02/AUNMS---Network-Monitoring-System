import sys
from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *
from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.inet import ICMP


class Ping(QWidget):
    def __init__(self):
        super().__init__()

        self.hostn = QLabel("Enter Address/Hostname to ping:")
        self.host = QLineEdit()

        self.startPingBtn = QPushButton()
        self.startPingBtn.setText('Ping')
        self.startPingBtn.clicked.connect(self.startPing)

        self.result = QTextEdit()
        self.result.setReadOnly(True)

        self.layoutPing = QVBoxLayout(self)
        self.layoutPing.addWidget(self.hostn)
        self.layoutPing.addWidget(self.host)
        self.layoutPing.addWidget(self.startPingBtn)
        self.layoutPing.addWidget(self.result)
        self.setLayout(self.layoutPing)

    def startPing(self):
        if(len(self.host.text()) >= 1):
            try:
                packet = IP(dst=self.host.text(), ttl=10)/ICMP()
                output = sr1(packet, timeout=2)
                if output is not None:
                    self.result.setText(output.summary())
            except socket.gaierror as e:
                self.result.setText(
                    "Invalid address/Could not get address info")
