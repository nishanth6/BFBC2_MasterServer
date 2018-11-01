from base64 import b64decode
from ConfigParser import NoOptionError
from threading import Timer
from time import strftime

from twisted.internet.protocol import Protocol

from Config import readFromConfig
from DataClasses import Client, Server
from Globals import Clients, Servers
from Framework import GameClient, GameServer
from Framework.ServerTypes import CLIENT, SERVER
from Logger import Log
from Utilities.Packet import Packet
from Utilities.RandomStringGenerator import GenerateRandomString


class HANDLER(Protocol):
    def __init__(self):
        self.CONNOBJ = None

        self.logger = None

        self.packetData = ""

    def connectionMade(self):
        self.ip, self.port = self.transport.client
        self.transport.setTcpNoDelay(True)

        if self.logger is None:
            if self.factory.serverType == CLIENT:
                self.logger = Log("PlasmaClient")
            elif self.factory.serverType == SERVER:
                self.logger = Log("PlasmaServer")
            else:
                self.logger = Log("UnknownTheater")

        self.logger.notification("[" + self.ip + ":" + str(self.port) + "] connected", 1)

        if self.CONNOBJ is None:
            if self.factory.serverType == CLIENT:
                self.CONNOBJ = Client()
                Clients.append(self.CONNOBJ)
            elif self.factory.serverType == SERVER:
                self.CONNOBJ = Server()
                self.CONNOBJ.gameID = self.factory.nextGameID
                self.factory.nextGameID += 1
                Servers.append(self.CONNOBJ)

            self.CONNOBJ.ipAddr = self.ip
            self.CONNOBJ.networkInt = self.transport

    def connectionLost(self, reason):
        self.logger.notification("[" + self.ip + ":" + str(self.port) + "] disconnected ", 1)

        if self.CONNOBJ is not None:
            self.CONNOBJ.IsUp = False

            if self.factory.serverType == CLIENT:
                Clients.remove(self.CONNOBJ)
            elif self.factory.serverType == SERVER:
                Servers.remove(self.CONNOBJ)

            del self

        return

    def dataReceived(self, data):
        packet_type = data[:4]
        packet_checksum = data.split(data[12:])[0].split(packet_type)[1]
        packet_id = Packet(None).getPacketID(packet_checksum[:4])
        packet_length = packet_checksum[4:]
        packet_data = data.split(packet_type + packet_checksum)[1]

        self.logger.notification("[" + self.ip + ":" + str(self.port) + "]<-- " + repr(data), 3)

        dataObj = Packet(packet_data).dataInterpreter()

        try:
            dataEncrypted = dataObj.get("PacketData", "data")

            self.packetData += dataEncrypted.replace("%3d", "=")

            if len(self.packetData) == int(dataObj.get("PacketData", "size")):
                dataObj = Packet(b64decode(self.packetData) + "\x00").dataInterpreter()
                self.packetData = ""
                isValidPacket = True
                self.CONNOBJ.plasmaPacketID += 1
            else:
                isValidPacket = False
        except:
            if packet_id == 0x80000000:  # Don't count it
                pass
            else:
                self.CONNOBJ.plasmaPacketID += 1

            isValidPacket = True

        if Packet(data).verifyPacketLength(packet_length) and isValidPacket:
            try:
                TXN = dataObj.get("PacketData", "TXN")

                if packet_type == "fsys":
                    if TXN == "Hello":
                        toSend = Packet().create()

                        self.CONNOBJ.locale = dataObj.get("PacketData", 'locale')  # Save locale for translated countryList and termsOfUse
                        currentTime = strftime('%b-%d-%Y %H:%M:%S UTC')

                        toSend.set("PacketData", "domainPartition.domain", "eagames")
                        toSend.set("PacketData", "messengerIp", readFromConfig("emulator", "emulator_ip"))
                        toSend.set("PacketData", "messengerPort", 0)  # Unknown data are being send to this port
                        toSend.set("PacketData", "domainPartition.subDomain", "BFBC2")
                        toSend.set("PacketData", "TXN", "Hello")
                        toSend.set("PacketData", "activityTimeoutSecs", 0)  # We could let idle clients disconnect here automatically?
                        toSend.set("PacketData", "curTime", currentTime)
                        toSend.set("PacketData", "theaterIp", readFromConfig("emulator", "emulator_ip"))

                        if self.factory.serverType == CLIENT:
                            toSend.set("PacketData", "theaterPort", str(readFromConfig("emulator", "theater_client_port")))
                        elif self.factory.serverType == SERVER:
                            toSend.set("PacketData", "theaterPort", str(readFromConfig("emulator", "theater_server_port")))

                        Packet(toSend).send(self, packet_type, 0x80000000, self.CONNOBJ.plasmaPacketID)

                        toSend = Packet().create()

                        toSend.set("PacketData", "TXN", "MemCheck")
                        toSend.set("PacketData", "memcheck.[]", 0)
                        toSend.set("PacketData", "type", 0)
                        toSend.set("PacketData", "salt", GenerateRandomString(9))

                        Packet(toSend).send(self, packet_type, 0x80000000, 0)
                    elif TXN == "MemCheck":
                        if self.CONNOBJ.IsUp:
                            if self.CONNOBJ.memcheck_timer is None:
                                self.CONNOBJ.memcheck_timer = Timer(500, self.send_memcheck)
                            else:
                                self.CONNOBJ.memcheck_timer = Timer(300, self.send_memcheck)

                            self.CONNOBJ.memcheck_timer.start()

                            if self.CONNOBJ.ping_timer is not None:
                                self.CONNOBJ.ping_timer.cancel()
                    elif TXN == "Ping":
                        if self.CONNOBJ.IsUp:
                            if self.CONNOBJ.ping_timer is not None:
                                self.CONNOBJ.ping_timer.cancel()

                            self.CONNOBJ.ping_timer = Timer(150, self.send_ping, [self, ])
                            self.CONNOBJ.ping_timer.start()
                    elif TXN == "GetPingSites":
                        toSend = Packet().create()
                        toSend.set("PacketData", "TXN", "GetPingSites")

                        emuIp = readFromConfig("emulator", "emulator_ip")

                        toSend.set("PacketData", "pingSite.[]", "4")
                        toSend.set("PacketData", "pingSite.0.addr", emuIp)
                        toSend.set("PacketData", "pingSite.0.type", "0")
                        toSend.set("PacketData", "pingSite.0.name", "gva")
                        toSend.set("PacketData", "pingSite.1.addr", emuIp)
                        toSend.set("PacketData", "pingSite.1.type", "1")
                        toSend.set("PacketData", "pingSite.1.name", "nrt")
                        toSend.set("PacketData", "pingSite.2.addr", emuIp)
                        toSend.set("PacketData", "pingSite.2.type", "2")
                        toSend.set("PacketData", "pingSite.2.name", "iad")
                        toSend.set("PacketData", "pingSite.3.addr", emuIp)
                        toSend.set("PacketData", "pingSite.3.type", "3")
                        toSend.set("PacketData", "pingSite.3.name", "sjc")
                        toSend.set("PacketData", "minPingSitesToPing", "0")

                        Packet(toSend).send(self, packet_type, 0x80000000, self.CONNOBJ.plasmaPacketID)
                    elif TXN == "Goodbye":
                        reason = dataObj.get("PacketData", "reason")
                        message = dataObj.get("PacketData", "message")

                        if reason == "GOODBYE_CLIENT_NORMAL":
                            if message.replace("%3d", "=") == "ErrType=0 ErrCode=0":
                                self.logger.notification("[" + self.ip + ":" + str(self.port) + '][fsys] Client disconnected normally!', 2)
                            else:
                                self.logger.notification("[" + self.ip + ":" + str(self.port) + '][fsys] Client disconnected because of error: ' + message.replace("%3d", "="), 2)
                        else:
                            self.logger.warning("[" + self.ip + ":" + str(self.port) + "] Unknown Goodbye reason!", 2)

                        self.CONNOBJ.IsUp = False
                    else:
                        self.logger.error("[" + self.ip + ":" + str(self.port) + ']<-- Got unknown fsys message (' + TXN + ")", 2)
                        raise KeyError
                elif packet_type == "acct":
                    if self.factory.serverType == CLIENT:
                        GameClient.acct(self, dataObj, TXN)
                    elif self.factory.serverType == SERVER:
                        GameServer.acct(self, dataObj, TXN)
                elif packet_type == "asso":
                    if self.factory.serverType == CLIENT:
                        GameClient.asso(self, dataObj, TXN)
                    elif self.factory.serverType == SERVER:
                        GameServer.asso(self, dataObj, TXN)
                elif packet_type == "xmsg":
                    if self.factory.serverType == CLIENT:
                        GameClient.xmsg(self, dataObj, TXN)
                    elif self.factory.serverType == SERVER:
                        self.logger.warning("<-- Got unexpected xmsg message from server!", 2)
                elif packet_type == "pres":
                    if self.factory.serverType == CLIENT:
                        GameClient.pres(self, dataObj, TXN)
                    elif self.factory.serverType == SERVER:
                        self.logger.warning("<-- Got unexpected pres message from server!", 2)
                elif packet_type == "rank":
                    if self.factory.serverType == CLIENT:
                        GameClient.rank(self, dataObj, TXN)
                    elif self.factory.serverType == SERVER:
                        GameServer.rank(self, dataObj, TXN)
                elif packet_type == "recp":
                    if self.factory.serverType == CLIENT:
                        GameClient.recp(self, dataObj, TXN)
                    elif self.factory.serverType == SERVER:
                        self.logger.warning("<-- Got unexpected recp message from server!", 2)
                else:
                    self.logger.error("[" + self.ip + ":" + str(self.port) + ']<-- Got unknown message type (' + packet_type + ")", 2)
                    raise KeyError
            except KeyError:
                self.send_error_packet(packet_type, dataObj.get("PacketData", "TXN"))
            except NoOptionError:
                self.logger.error("Got incorrect packet from client (" + self.ip + ":" + str(self.port) + ")! Disconnecting...", 1)
                self.transport.loseConnection()
                return
        elif not isValidPacket:
            pass
        else:
            self.CONNOBJ.plasmaPacketID += 1
            self.logger.error("Packet Length is different than the received data length! "
                              "(" + self.ip + ":" + str(self.port) + "). Disconnecting for safety purposes...", 2)
            self.transport.loseConnection()

    def send_error_packet(self, packet_type, TXN):
        toSend = Packet().create()
        toSend.set("PacketData", "localizedMessage", "System Error%3a99")
        toSend.set("PacketData", "TID", str(self.CONNOBJ.plasmaPacketID))
        toSend.set("PacketData", "errorContainer.[]", "0")
        toSend.set("PacketData", "TXN", TXN)
        toSend.set("PacketData", "errorCode", "99")
        Packet(toSend).send(self, packet_type, "ferr", self.CONNOBJ.plasmaPacketID)

    def send_memcheck(self):
        toSend = Packet().create()

        toSend.set("PacketData", "TXN", "MemCheck")
        toSend.set("PacketData", "memcheck.[]", 0)
        toSend.set("PacketData", "type", 0)
        toSend.set("PacketData", "salt", GenerateRandomString(9))

        if self.CONNOBJ.IsUp:
            Packet(toSend).send(self, "fsys", 0x80000000, 0)

    def send_ping(self):
        toSend = Packet().create()
        toSend.set("PacketData", "TXN", "Ping")

        if self.CONNOBJ.IsUp:
            Packet(toSend).send(self, "fsys", 0x80000000, 0)
