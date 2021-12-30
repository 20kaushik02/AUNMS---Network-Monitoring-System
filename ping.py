from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *
from scapy.all import *
from scapy.layers.inet import IP, ICMP, icmpcodes, icmptypes


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
                packet = IP(dst=self.host.text())/ICMP()
                result = ""
                
                for i in range(1, 6):
                    output = sr1(packet, timeout=3, verbose=0)
                    if output is not None:
                        res_type = icmptypes[output.type]
                        res_code = ""
                        if output.type in icmpcodes:
                            res_code = " - "+icmpcodes[output.type][output.code]
                        ping_time = int((output.time - packet.sent_time)*1000)

                        result += "{}{} from {}:\ttime={}ms\tTTL={}\n".format(
                            res_type,
                            res_code,
                            packet[IP].dst,
                            ping_time,
                            packet[IP].ttl
                        )
                    else:
                        result += "Request timed out.\n"
                    self.result.setText(result)
            except socket.gaierror:
                self.result.setText(
                    "Invalid address/Could not get address info")
