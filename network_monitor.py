from PyQt5.QtGui     import *
from PyQt5.QtCore    import *
from PyQt5.QtWidgets import *
from network_monitor_thread import NetworkMonitorThread
from scapy.all import *
import sys, csv

class NetworkMonitor(QMainWindow):
    def __init__(self):
        super().__init__()
        self.interfaceSelected = None
        self.autoscroll = True
        self.layout = QVBoxLayout()
        
        self._createMenuBar()
        self._createTable()
        self.setLayout(self.layout)
    
    def _createTable(self):
        self.tableWidget = QTableWidget()
        self.tableWidget.setStyleSheet('border-bottom: 1px solid #d6d9dc')
        
        self.tableWidget.setTabKeyNavigation(False)
        self.tableWidget.setProperty("showDropIndicator", False)
        self.tableWidget.setDragDropOverwriteMode(False)
        self.tableWidget.setSelectionMode(QAbstractItemView.SingleSelection)
        self.tableWidget.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.tableWidget.setShowGrid(True)
        self.tableWidget.setGridStyle(Qt.NoPen)
        self.tableWidget.setRowCount(0)
        self.tableWidget.setColumnCount(7)
        self.tableWidget.setHorizontalHeaderLabels(["No", "Time", "Source", "Destination", "Protocol", "Length", "Info"])
        self.tableWidget.horizontalHeader().setVisible(True)
        self.tableWidget.horizontalHeader().setCascadingSectionResizes(True)
        self.tableWidget.horizontalHeader().setHighlightSections(False)
        self.tableWidget.horizontalHeader().setSortIndicatorShown(True)
        self.tableWidget.verticalHeader().setVisible(False)
        self.tableWidget.setSortingEnabled(False)
        self.tableWidget.setEditTriggers(QTableWidget.NoEditTriggers)
        self.tableWidget.setAutoScroll(True)
        
        self.tableWidget.horizontalHeader(). setSectionResizeMode(6, QHeaderView.Stretch)
        sizePolicy = QSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.tableWidget.sizePolicy().hasHeightForWidth())
        self.tableWidget.setSizePolicy(sizePolicy)
        self.setCentralWidget(self.tableWidget)
   
    def _createMenuBar(self):
        self.menubar = QMenuBar(self)
        self.setMenuBar(self.menubar)
        self.menubar.setStyleSheet('font-size: 11pt')
        
        self.actionStart = QAction('Start', self)
        
        self.actionStart.triggered.connect(self.packetSniff)
        self.menubar.addAction(self.actionStart)
        
        self.menubar.addSeparator()
        
        self.actionStop = QAction('Stop', self)
        self.menubar.addAction(self.actionStop)
        
        self.menubar.addSeparator()
        
        self.actionPickInterface = QAction('Choose Interface', self)
        self.actionPickInterface.triggered.connect(self.interfaceDialog)
        self.menubar.addAction(self.actionPickInterface) 
        
        self.actionClear = QAction('Clear', self)
        self.actionClear.triggered.connect(self.packetClear)
        self.menubar.addAction(self.actionClear) 
        
        self.menubar.addSeparator()
        
        self.actionSaveCSV = QAction('Save as CSV', self)
        self.actionSaveCSV.triggered.connect(self.savePacketsCSV)
        
        self.actionSavePCAP = QAction('Save as pcap', self)
        self.actionSavePCAP.triggered.connect(self.savePacketsPCAP)
        
        self.actionSaveBLIP = QAction('Log Violations', self)
        self.actionSaveBLIP.triggered.connect(self.savePacketsBLIP)
        
        self.saveMenu = QMenu('Save', self)
        self.saveMenu.addAction(self.actionSaveCSV)
        self.saveMenu.addAction(self.actionSavePCAP)
        self.saveMenu.addAction(self.actionSaveBLIP)
        self.menubar.addMenu(self.saveMenu)
        
        self.actionScroll = QAction('Disable Auto Scroll', self)
        self.actionScroll.triggered.connect(self.autoScrollSet)
        self.actionScroll.setCheckable(True)
        self.actionScroll.setChecked(True)
        
        self.menubar.addAction(self.actionScroll) 
        
    def autoScrollSet(self):
        print(self.actionScroll.isChecked())
        if (self.actionScroll.isChecked() == True):
            self.tableWidget.scrollToBottom()
            self.actionScroll.setText('Disable Auto Scroll')
        if (self.actionScroll.isChecked() == False):
            self.actionScroll.setText('Enable Auto Scroll')
        
    def packetSniff(self):
        if self.interfaceSelected == None:
            self.interfaceDialog()
        
        print("Monitoring - {}".format(
            self.interfaceSelected
        ))
        
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
            self.thread.quit()
            self.actionStart.setEnabled(True)
            self.actionStop.setEnabled(False)
            self.actionPickInterface.setEnabled(True)
            
            print("Terminating thread")
            self.thread.quit()
        
    def packetClear(self):
        self.thread.terminate()
        self.tableWidget.clearContents()
        self.tableWidget.setRowCount(0)
    
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
        
        self.setColortoRow(self.tableWidget, rowpos, tableData['RowColor'])
        
        self.vbar = self.tableWidget.verticalScrollBar()
        self._scroll = self.vbar.value() == self.vbar.maximum()
        
        if self._scroll and self.actionScroll.isChecked():
            self.tableWidget.scrollToBottom()
        
    def setColortoRow(self, table, rowIndex, color):
        for j in range(table.columnCount()):
            table.item(rowIndex, j).setBackground(color)
            
    def savePacketsPCAP(self):
        path = QFileDialog.getSaveFileName(self, 'Save File', '', 'pcap(*.pcap)')
        path = str(path[0])
        wrpcap(path, self.worker.packetList)
    
    def savePacketsBLIP(self):
        path = QFileDialog.getSaveFileName(self, 'Save File', '', 'pcap(*.pcap)')
        path = str(path[0])
        wrpcap(path, self.worker.blackListAccess)
        self.worker.blackListAccess = []
    
    def savePacketsCSV(self):
        path = QFileDialog.getSaveFileName(self, 'Save File', '', 'CSV(*.csv)')
        with open(path[0], 'w') as stream:
            writer = csv.writer(stream, lineterminator='\n')
            for row in range(self.tableWidget.rowCount()):
                rowdata = []
                for column in range(self.tableWidget.columnCount()):
                    item = self.tableWidget.item(row, column)
                    if item is not None:
                        rowdata.append(item.text())
                    else:
                        rowdata.append('')

                writer.writerow(rowdata)
    
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
        
