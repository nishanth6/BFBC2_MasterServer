from twisted.internet.protocol import Protocol, DatagramProtocol

from Framework import GameClient, GameServer
from Framework.ServerTypes import CLIENT, SERVER
from Globals import Clients, Servers
from Logger import Log
from Utilities.Packet import Packet


class TCPHandler(Protocol):
    def __init__(self):
        self.CONNOBJ = None

        self.logger = None

    def connectionMade(self):
        self.ip, self.port = self.transport.client
        self.transport.setTcpNoDelay(True)

        if self.logger is None:
            if self.factory.serverType == CLIENT:
                self.logger = Log("TheaterClient")
            elif self.factory.serverType == SERVER:
                self.logger = Log("TheaterServer")
            else:
                self.logger = Log("UnknownTheater")

        self.logger.notification("[" + self.ip + ":" + str(self.port) + "] connected", 1)

    def connectionLost(self, reason):
        self.logger.notification("[" + self.ip + ":" + str(self.port) + "] disconnected ", 1)

        if self.CONNOBJ is not None:
            self.CONNOBJ.IsUp = False
            del self

        return

    def dataReceived(self, data):
        packet_type = data[:4]
        packets = data.split('\n\x00')

        dataObjs = []

        if len(packets) > 2:
            for packet in packets:
                fixedPacketType = packet[:4]
                fixedPacket = packet[12:]

                if len(fixedPacket) == 0:
                    break
                else:
                    dataObjs.append({"data": Packet(fixedPacket + "\n\x00").dataInterpreter(), "type": fixedPacketType})
        else:
            dataObjs.append({"data": Packet(packets[0][12:] + "\n\x00").dataInterpreter(), "type": packet_type})

        self.logger.notification("[" + self.ip + ":" + str(self.port) + "]<-- " + repr(data), 3)

        for dataObj in dataObjs:
            if dataObj['type'] == "CONN":
                tid = dataObj['data'].get("PacketData", "TID")
                prot = dataObj['data'].get("PacketData", "PROT")

                toSend = Packet().create()
                toSend.set("PacketData", "TID", str(tid))
                toSend.set("PacketData", "TIME", "0")
                toSend.set("PacketData", "activityTimeoutSecs", "240")
                toSend.set("PacketData", "PROT", prot)

                Packet(toSend).send(self, dataObj['type'], 0x00000000, 0)
            elif dataObj['type'] == "USER":
                lkey = dataObj['data'].get("PacketData", "LKEY")

                if self.factory.serverType == CLIENT:
                    for client in Clients:
                        if client.personaSessionKey == lkey:
                            self.CONNOBJ = client
                elif self.factory.serverType == SERVER:
                    for server in Servers:
                        if server.personaSessionKey == lkey:
                            self.CONNOBJ = server
                            self.CONNOBJ.theaterInt = self

                if self.CONNOBJ is None:
                    self.transport.loseConnection()
                else:
                    toSend = Packet().create()
                    toSend.set("PacketData", "TID", str(dataObj['data'].get("PacketData", "TID")))
                    toSend.set("PacketData", "NAME", self.CONNOBJ.personaName)

                    Packet(toSend).send(self, "USER", 0x00000000, 0)
            elif dataObj['type'] == "GDAT":
                if self.factory.serverType == CLIENT:
                    GameClient.GDAT(self, dataObj['data'])
                elif self.factory.serverType == SERVER:
                    self.logger.warning("<-- Got unexpected GDAT message from server!", 2)
            elif dataObj['type'] == "LLST":
                if self.factory.serverType == CLIENT:
                    GameClient.LLST(self, dataObj['data'])
                elif self.factory.serverType == SERVER:
                    self.logger.warning("<-- Got unexpected LLST message from server!", 2)
            elif dataObj['type'] == "GLST":
                if self.factory.serverType == CLIENT:
                    GameClient.GLST(self, dataObj['data'])
                elif self.factory.serverType == SERVER:
                    self.logger.warning("<-- Got unexpected GLST message from server!", 2)
            elif dataObj['type'] == "CGAM":
                if self.factory.serverType == CLIENT:
                    self.logger.warning("<-- Got unexpected CGAM message from client!", 2)
                elif self.factory.serverType == SERVER:
                    GameServer.CGAM(self, dataObj['data'])
            elif dataObj['type'] == "UBRA":
                if self.factory.serverType == CLIENT:
                    self.logger.warning("<-- Got unexpected UBRA message from client!", 2)
                elif self.factory.serverType == SERVER:
                    GameServer.UBRA(self, dataObj['data'])
            elif dataObj['type'] == "UGAM":
                if self.factory.serverType == CLIENT:
                    self.logger.warning("<-- Got unexpected UGAM message from client!", 2)
                elif self.factory.serverType == SERVER:
                    GameServer.UGAM(self, dataObj['data'])
            elif dataObj['type'] == "UGDE":
                if self.factory.serverType == CLIENT:
                    self.logger.warning("<-- Got unexpected UGDE message from client!", 2)
                elif self.factory.serverType == SERVER:
                    GameServer.UGDE(self, dataObj['data'])
            elif dataObj['type'] == "EGAM":
                if self.factory.serverType == CLIENT:
                    GameClient.EGAM(self, dataObj['data'])
                elif self.factory.serverType == SERVER:
                    self.logger.warning("<-- Got unexpected EGAM message from server!", 2)
            elif dataObj['type'] == "EGRS":
                if self.factory.serverType == CLIENT:
                    self.logger.warning("<-- Got unexpected EGRS message from client!", 2)
                elif self.factory.serverType == SERVER:
                    GameServer.EGRS(self, dataObj['data'])
            elif dataObj['type'] == "ECNL":
                if self.factory.serverType == CLIENT:
                    GameClient.ECNL(self, dataObj['data'])
                elif self.factory.serverType == SERVER:
                    self.logger.warning("<-- Got unexpected ECNL message from server!", 2)
            elif dataObj['type'] == "PENT":
                if self.factory.serverType == CLIENT:
                    self.logger.warning("<-- Got unexpected PENT message from server!", 2)
                elif self.factory.serverType == SERVER:
                    GameServer.PENT(self, dataObj['data'])
            elif dataObj['type'] == "PLVT":
                if self.factory.serverType == CLIENT:
                    self.logger.warning("<-- Got unexpected PLVT message from server!", 2)
                elif self.factory.serverType == SERVER:
                    GameServer.PLVT(self, dataObj['data'])
            else:
                self.logger.error("[" + self.ip + ":" + str(self.port) + ']<-- Got unknown message type (' + dataObj['type'] + ")", 2)
                self.transport.loseConnection()


class UDPHandler(DatagramProtocol):
    def __init__(self):
        self.logger = Log("TheaterUDP")

    def datagramReceived(self, datagram, addr):
        packet_type = datagram[:4]
        packet_data = datagram[12:]

        dataObj = Packet(packet_data).dataInterpreter()

        self.logger.notification("[" + addr[0] + ":" + str(addr[1]) + "][UDP]<-- " + repr(datagram), 3)

        if packet_type == 'ECHO':
            toSend = Packet().create()

            toSend.set("PacketData", "TXN", "ECHO")
            toSend.set("PacketData", "IP", addr[0])
            toSend.set("PacketData", "PORT", str(addr[1]))
            toSend.set("PacketData", "ERR", "0")
            toSend.set("PacketData", "TYPE", "1")
            toSend.set("PacketData", "TID", str(dataObj.get("PacketData", "TID")))

            Packet(toSend).send(self, "ECHO", 0x00000000, 0, addr)
        else:
            self.logger.warning("[" + addr[0] + ":" + str(addr[1]) + "][UDP] Received unknown packet type! (" + packet_type + ")", 2)

