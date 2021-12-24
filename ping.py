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
                output = sr1(packet, timeout=2)
                if output is not None:
                    res_type = icmptypes[output.type]
                    res_code = ""
                    if output.type in icmpcodes:
                        res_code = " - "+icmpcodes[output.type][output.code]
                    ping_time = int((output.time - packet.sent_time)*1000)

                    self.result.setText(
                        "Ping results:\nSummary: {}\n\nType:\t\t{}{}\nTime:\t\t{}ms\nSource:\t\t{}\nDestination:\t{}\
                            \nTTL:\t\t{}".format(
                                output.summary(),
                                res_type,
                                res_code,
                                ping_time,
                                packet[IP].src,
                                packet[IP].dst,
                                packet[IP].ttl
                        )
                    )
                else:
                    self.result.setText("Request timed out.")
            except socket.gaierror:
                self.result.setText(
                    "Invalid address/Could not get address info")
