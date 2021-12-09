from PyQt5.QtGui     import *
from PyQt5.QtCore    import *
from PyQt5.QtWidgets import *
from network_monitor_thread import NetworkMonitorThread
from scapy.all import *

class NetworkMonitor(QMainWindow):
    def __init__(self):
        super().__init__()
        self.interfaceSelected = None
        
        self.layout = QVBoxLayout()
        
        self._createToolBar()
        self._createTable()
        self.setLayout(self.layout)
    
    def _createTable(self):
        self.tableWidget = QTableWidget()
        self.tableWidget.setTabKeyNavigation(False)
        self.tableWidget.setProperty("showDropIndicator", False)
        self.tableWidget.setDragDropOverwriteMode(False)
        self.tableWidget.setSelectionMode(QAbstractItemView.SingleSelection)
        self.tableWidget.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.tableWidget.setShowGrid(False)
        self.tableWidget.setGridStyle(Qt.NoPen)
        self.tableWidget.setRowCount(0)
        self.tableWidget.setColumnCount(7)
        self.tableWidget.setHorizontalHeaderLabels(["No", "Time", "Source", "Destination", "Protocol", "Length", "Info"])
        self.tableWidget.horizontalHeader().setVisible(True)
        self.tableWidget.horizontalHeader().setCascadingSectionResizes(True)
        self.tableWidget.horizontalHeader().setHighlightSections(False)
        self.tableWidget.horizontalHeader().setSortIndicatorShown(True)
        self.tableWidget.verticalHeader().setVisible(False)
        self.tableWidget.setSortingEnabled(True)
        self.tableWidget.setEditTriggers(QTableWidget.NoEditTriggers)
        
        self.tableWidget.horizontalHeader(). setSectionResizeMode(6, QHeaderView.Stretch)
        sizePolicy = QSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.tableWidget.sizePolicy().hasHeightForWidth())
        self.tableWidget.setSizePolicy(sizePolicy)
        self.setCentralWidget(self.tableWidget)
   
    def _createToolBar(self):
        self.toolbar = QToolBar(self)
        self.addToolBar(self.toolbar)

        self.toolbar.setStyleSheet('font-size: 9pt')
        
        self.actionStart = QAction('Start', self)
        
        self.actionStart.triggered.connect(self.packetSniff)
        self.toolbar.addAction(self.actionStart)
        
        self.toolbar.addSeparator()
        
        self.actionStop = QAction('Stop', self)
        self.toolbar.addAction(self.actionStop)
        
        self.toolbar.addSeparator()
        
        self.actionPickInterface = QAction('Choose Interface', self)
        self.actionPickInterface.triggered.connect(self.interfaceDialog)
        self.toolbar.addAction(self.actionPickInterface) 
        
        self.actionClear = QAction('Clear', self)
        self.actionClear.triggered.connect(self.packetClear)
        self.toolbar.addAction(self.actionClear) 
        
        self.toolbar.addSeparator()
        self.toolbar.addAction("Save") 
    
    def packetSniff(self):
        if self.interfaceSelected == None:
            self.interfaceDialog()
        
        print(f"Monitoring - {self.interfaceSelected}")
        
        self.actionStart.setEnabled(False)
        self.actionStop.setEnabled(True)
        self.actionClear.setEnabled(True)
        self.actionPickInterface.setEnabled(False)
        
        self.thread = QThread()
        self.worker = NetworkMonitorThread(interface = self.interfaceSelected)
        self.worker.moveToThread(self.thread)
        
        self.thread.started.connect(self.worker.startSniff)
        self.actionStop.triggered.connect(self.worker.endSniff)
        
        self.worker.packetData.connect(self.addPacketToTableWidget)
        self.worker.quitBool.connect(self.stopSniff)
        self.thread.start()
    
    quitBool = pyqtSignal()
    def stopSniff(self, quitBool):
        print(quitBool)
        if(quitBool == 1):
            self.actionStart.setEnabled(True)
            self.actionStop.setEnabled(False)
            self.actionPickInterface.setEnabled(True)
            
            print("Terminating thread")
            self.thread.terminate()
        
    def packetClear(self):
        self.actionStart.setEnabled(False)
        self.actionStop.setEnabled(True)
        
        self.thread.terminate()
        self.tableWidget.clearContents()
        self.tableWidget.setRowCount(0)
        self.thread.start()
    
    def interfaceDialog(self):
        self.interfaceDiag = InterfacePick() 
        self.interfaceDiag.exec_()
        if hasattr(self.interfaceDiag, 'interfaceName'):
            self.interfaceSelected = self.interfaceDiag.interfaceName
            print(self.interfaceSelected)
    
    packetData = pyqtSignal()
    def addPacketToTableWidget(self, packetData):
        tableData = packetData[1]
        rowpos = self.tableWidget.rowCount()
        self.tableWidget.insertRow(rowpos)
        self.tableWidget.setItem(rowpos, 0, QTableWidgetItem(str(rowpos+1)))
        self.tableWidget.setItem(rowpos, 1, QTableWidgetItem(str(tableData['timestamp'])))
        self.tableWidget.setItem(rowpos, 2, QTableWidgetItem(tableData['source']))
        self.tableWidget.setItem(rowpos, 3, QTableWidgetItem(tableData['destination']))
        self.tableWidget.setItem(rowpos, 4, QTableWidgetItem(tableData['Protocol']))
        self.tableWidget.setItem(rowpos, 5, QTableWidgetItem(str(tableData['length'])))
        self.tableWidget.setItem(rowpos, 6, QTableWidgetItem(tableData['info']))
        
class InterfacePick(QDialog):
    def __init__(self, parent=None):
        super().__init__()
        self.setWindowTitle('Choose Interface to Monitor')
        self.width = 400
        self.height = 400
        
        self.setMinimumSize(self.width, self.height)
        
        self.interfaceList = QListWidget()
        self.listInterfaces()
        
        self.acceptInterface = QPushButton()
        self.acceptInterface.setText('Accept')
        self.acceptInterface.clicked.connect(self.acceptInterfaceFn)
        
        self.layout = QVBoxLayout()
        self.layout.addWidget(self.interfaceList)
        self.layout.addWidget(self.acceptInterface)
        self.setLayout(self.layout)
        
    def listInterfaces(self):
        for iface_name in sorted(ifaces.keys()):
            dev = ifaces[iface_name]
            mac = dev.mac
            if iface_name != LOOPBACK_NAME:
                mac = conf.manufdb._resolve_MAC(mac)
            
            if str(dev.ip) != "None" and not str(dev.name).startswith("VM"):
                item = '{:40s}\t{}'.format(str(dev.name).strip(), str(dev.ip).strip())
                self.interfaceList.addItem(item)
            
    
    def acceptInterfaceFn(self):
        self.idx = self.interfaceList.selectedIndexes()
        self.interfaceName = self.idx[0].data().split('\t')[0].strip()        
        self.close()
        
