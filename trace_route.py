from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *
from scapy.all import *
from scapy.layers.inet import traceroute


class TraceRoute(QWidget):
    def __init__(self):
        super().__init__()

        self.hostn = QLabel("Enter Address/Hostname to trace:")
        self.host = QLineEdit()

        self.startTraceBtn = QPushButton()
        self.startTraceBtn.setText('Trace Route')
        self.startTraceBtn.clicked.connect(self.startTrace)

        self.result = QTextEdit()
        self.result.setReadOnly(True)

        self.layoutTrace = QVBoxLayout(self)
        self.layoutTrace.addWidget(self.hostn)
        self.layoutTrace.addWidget(self.host)
        self.layoutTrace.addWidget(self.startTraceBtn)
        self.layoutTrace.addWidget(self.result)
        self.setLayout(self.layoutTrace)

    def startTrace(self):
        if(len(self.host.text()) >= 1):
            try:
                result, unans = traceroute(
                    target=self.host.text(), dport=80, verbose=0)
                output = []
                output.append("\tRoute path\t\tResponse time")
                result = sorted(result, key=lambda x: x[0].ttl)

                for snd, rcv in result:
                    output.append(
                        str("{}\t{}\t\t{} ms".format(
                            snd.ttl,
                            rcv.src,
                            (int((rcv.time - snd.sent_time)*1000))
                        )))
                output.append("\nUnanswered packets: {}".format(
                    len(unans)
                ))
                self.result.setText('\n'.join(output))
            except socket.gaierror:
                self.result.setText(
                    "Invalid address/Could not get address info")
