import sys
from PyQt5.QtGui     import *
from PyQt5.QtCore    import *
from PyQt5.QtWidgets import *
from scapy.all import *

from ping import Ping
from trace_route import TraceRoute
from network_monitor import NetworkMonitor
from network_devices import NetworkDevices

class AUNMS(QWidget):
    def __init__(self):
        super().__init__()
        
        self.setWindowTitle("AU Network Monitor")
        self.width = 1600
        self.height = 900
        
        self.setMinimumSize(self.width, self.height)
        
        self.tabwidget = QTabWidget()
        self.tabwidget.setStyleSheet('font-size: 12pt')
        
        self.tabwidget.addTab(NetworkMonitor(), "Network Monitor")
        self.tabwidget.addTab(TraceRoute(), "Trace Route")
        self.tabwidget.addTab(Ping(), "Ping")
        self.tabwidget.addTab(NetworkDevices(), "Network Devices")
        
        self.layout = QVBoxLayout()
        self.layout.addWidget(self.tabwidget)
        
        self.setLayout(self.layout)
     
def main():
    app = QApplication(sys.argv)
    aunms = AUNMS()
    aunms.show()
    app.exec()
    
if __name__ == "__main__":
    main()