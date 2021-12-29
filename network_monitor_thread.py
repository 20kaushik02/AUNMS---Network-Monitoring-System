from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *
from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.l2 import *


class NetworkMonitorThread(QObject):
    def __init__(self, interface, parent=None):
        QObject.__init__(self, parent=parent)
        self.interface = interface
        self.packetList = []
        self.end = False

    quitBool = pyqtSignal(int)

    def endSniff(self):
        QApplication.processEvents()
        print("Ending")
        self.end = True
        self.quitBool.emit(1)

    def sniffStatus(self):
        QApplication.processEvents()
        return self.end

    def getLayers(self, packet):
        QApplication.processEvents()
        layers = []
        counter = 0
        while True:
            layer = packet.getlayer(counter)
            if layer is not None:
                if layer.name is not "Padding":
                    layers.append(layer.name)
            else:
                break
            counter += 1
        return layers

    packetData = pyqtSignal(tuple)

    def handlePacket(self, packet):
        self.packetList.append(packet)
        QApplication.processEvents()
        tableViewPart = dict()
        tableViewPart['timestamp'] = packet.time
        try:
            tableViewPart['source'] = packet.getlayer("IP").src
            tableViewPart['destination'] = packet.getlayer("IP").dst
        except:
            tableViewPart['source'] = packet.src
            tableViewPart['destination'] = packet.dst
        tableViewPart['length'] = len(packet)
        tableViewPart['layers'] = self.getLayers(packet)

        QApplication.processEvents()
        (protocol, info) = self.getInfo(packet)
        tableViewPart['info'] = info
        if protocol:
            tableViewPart['Protocol'] = protocol
        elif IP in packet:
            tableViewPart['Protocol'] = "IP"
        else:
            tableViewPart['Protocol'] = "Other"
        QApplication.processEvents()
        self.packetData.emit((packet, tableViewPart))

    def getInfo(self, packet):
        QApplication.processEvents()
        info = ""
        protocol = ""
        if UDP in packet:
            protocol = "UDP"
            info = "{} -> {} len={} chksum={}".format(
                packet[UDP].sport,
                packet[UDP].dport,
                packet[UDP].len,
                packet[UDP].chksum
            )
        elif TCP in packet:
            flags = {
                'F': 'FIN',
                'S': 'SYN',
                'R': 'RST',
                'P': 'PSH',
                'A': 'ACK',
                'U': 'URG',
                'E': 'ECE',
                'C': 'CWR',
            }

            flgs = str([flags[x] for x in packet.sprintf('%TCP.flags%')])
            protocol = "TCP"
            info = "{} -> {} {} seq={} ack={} window={}".format(
                packet[TCP].sport,
                packet[TCP].dport,
                flgs,
                packet[TCP].seq,
                packet[TCP].ack,
                packet[TCP].window
            )
        elif ICMP in packet:
            protocol = "ICMP"
            info = "type={} code={} chksum={}".format(
                packet[ICMP].type,
                packet[ICMP].code,
                packet[ICMP].chksum,
            )
        elif ARP in packet:
            protocol = "ARP"
            info = "hwtype={} ptype={} hwlen={} plen={} op={}".format(
                packet[ARP].hwtype,
                packet[ARP].ptype,
                packet[ARP].hwlen,
                packet[ARP].plen,
                packet[ARP].op
            )
        QApplication.processEvents()
        return (protocol, info)

    def startSniff(self):
        while(self.end == False):
            QApplication.processEvents()
            self.pkts = sniff(
                count=0,
                iface=self.interface,
                prn=self.handlePacket,
                timeout=2,
                stop_filter=lambda x: self.sniffStatus()
            )
            QApplication.processEvents()