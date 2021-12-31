from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *
from scapy.all import *
from scapy.layers.inet import IP, ICMP
from network_monitor import InterfacePick


class NetworkDevices(QWidget):
	def __init__(self):
		super().__init__()
		self.networkIP = ''
		self.layout = QGridLayout()

		self.header = QLabel("Connected hosts on the network:")

		self.interfbtn = QPushButton()
		self.interfbtn.setFixedSize(300, 40)
		self.interfbtn.setText('[Select Network]')
		self.interfbtn.clicked.connect(self.networkInterface)

		self.refreshbtn = QPushButton()
		self.refreshbtn.setFixedSize(350, 40)
		self.refreshbtn.setText('Refresh Status')
		self.refreshbtn.clicked.connect(self.getConnectedDevices)

		self._createTable()
		self.layout.addWidget(self.header, 0, 0)
		self.layout.addWidget(self.interfbtn, 0, 1)
		self.layout.addWidget(self.refreshbtn, 0, 2)
		self.layout.addWidget(self.tableWidget, 1, 0, 1, 3)

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
		self.tableWidget.setColumnCount(3)
		self.tableWidget.setHorizontalHeaderLabels(["IP", "MAC", "Status"])
		self.tableWidget.horizontalHeader().setVisible(True)
		self.tableWidget.horizontalHeader().setCascadingSectionResizes(True)
		self.tableWidget.horizontalHeader().setHighlightSections(False)
		self.tableWidget.horizontalHeader().setSortIndicatorShown(True)
		self.tableWidget.verticalHeader().setVisible(False)
		self.tableWidget.setSortingEnabled(False)
		self.tableWidget.setEditTriggers(QTableWidget.NoEditTriggers)
		self.tableWidget.setAutoScroll(True)

		self.tableWidget.horizontalHeader(). setSectionResizeMode(QHeaderView.Stretch)
		sizePolicy = QSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
		sizePolicy.setHorizontalStretch(0)
		sizePolicy.setVerticalStretch(0)
		sizePolicy.setHeightForWidth(
		    self.tableWidget.sizePolicy().hasHeightForWidth())
		self.tableWidget.setSizePolicy(sizePolicy)
	
	def getConnectedDevices(self):
		while self.networkIP is '':
			sys.stdout.write('\a')
			sys.stdout.flush()
			self.networkInterface()
		
		output = subprocess.check_output(["arp", "-a"])	#get ARP table
		output = output.partition(bytes(f"Interface: {self.networkIP}", 'utf-8'))[2]
		output = output.split(b'Interface')[0]
		output = output.split()[7:]
		
		self.tableWidget.clearContents()
		self.tableWidget.setRowCount(0)

		for i in range(0, len(output), 3):
			entry_ip = str(output[i], encoding='utf-8')
			entry_mac = str(output[i+1], encoding='utf-8').replace("-",":")
			
			if entry_mac == "ff:ff:ff:ff:ff:ff":
				continue
			mul_addr = int(entry_ip.split('.')[0])
			if mul_addr >= 224 and mul_addr < 240:
				continue

			arpData = dict()
			arpData['IP'] = entry_ip
			arpData['MAC'] = entry_mac
			arpData['Status'] = self.refreshStatus(entry_ip)

			self.addArpToTableWidget(arpData)
			
	def addArpToTableWidget(self, arpData):
		rowpos = self.tableWidget.rowCount()
		self.tableWidget.insertRow(rowpos)

		ip_item = QTableWidgetItem(arpData['IP'])
		ip_item.setTextAlignment(Qt.AlignCenter)
		mac_item = QTableWidgetItem(arpData['MAC'])
		mac_item.setTextAlignment(Qt.AlignCenter)
		status_item = QTableWidgetItem(arpData['Status'])
		status_item.setTextAlignment(Qt.AlignCenter)
		
		self.tableWidget.setItem(rowpos, 0, ip_item)
		self.tableWidget.setItem(rowpos, 1, mac_item)
		self.tableWidget.setItem(rowpos, 2, status_item)

		self.vbar = self.tableWidget.verticalScrollBar()
		self._scroll = self.vbar.value() == self.vbar.maximum()

	def networkInterface(self):
		self.interfaceDiag = InterfacePick()
		self.interfaceDiag.exec_()
		if hasattr(self.interfaceDiag, 'interfaceIP') and hasattr(self.interfaceDiag, 'interfaceName'):
			self.networkIP = self.interfaceDiag.interfaceIP
			self.interfbtn.setText(self.interfaceDiag.interfaceName)
	
	def refreshStatus(self, deviceIP):
		try:
			packet = IP(dst=deviceIP)/ICMP()
			
			status = 'Unresponsive'
			for _ in range(3):
				output = sr1(packet, timeout=2, verbose=0)
				if output is not None:
					if output.type is 0:
						status = 'Reachable - {}ms'.format(
							int((output.time - packet.sent_time)*1000)
						)
						break
			return status
		except socket.gaierror:
			return 'Invalid address'