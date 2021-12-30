from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *
from scapy.all import *
from scapy.layers.l2 import ARP, Ether


class NetworkDevices(QWidget):
	def __init__(self):
		super().__init__()
		self.layout = QGridLayout()

		self.header = QLabel("Connected hosts on the network:")

		self.refreshbtn = QPushButton()
		self.refreshbtn.setFixedSize(350, 40)
		self.refreshbtn.setText('Refresh Status')
		self.refreshbtn.clicked.connect(self.refreshStatus)

		self._createTable()
		self.layout.addWidget(self.header, 0, 0)
		self.layout.addWidget(self.refreshbtn, 0, 1)
		self.layout.addWidget(self.tableWidget, 1, 0, 1, 2)

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

	def refreshStatus(self):
		target_ip = "192.168.1.1/16"
		packet = Ether("ff:ff:ff:ff:ff:ff")/ARP(pdst=target_ip)

		result = srp1(packet, timeout=2, verbose=0)

		if result is not None:
			devices = []
			for sent, received in result:
				# for each response, append ip and mac address to `clients` list
				devices.append({'ip': received.psrc, 'mac': received.hwsrc})

			# print clients
			print("Available devices in the network:")
			print("IP" + " "*18+"MAC")
			for client in devices:
				print("{:16}    {}".format(client['ip'], client['mac']))