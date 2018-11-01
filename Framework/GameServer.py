from ConfigParser import ConfigParser
from base64 import b64decode

from Database import Database
from Globals import Clients
from Utilities.Packet import Packet
from Utilities.RandomStringGenerator import GenerateRandomString

db = Database()


def acct(self, data, txn):
    toSend = Packet().create()

    if txn == 'NuLogin':
        toSend.set("PacketData", "TXN", "NuLogin")

        returnEncryptedInfo = int(data.get("PacketData", "returnEncryptedInfo"))  # If 1 - User wants to store login information

        try:
            nuid = data.get('PacketData', "nuid")
            password = data.get('PacketData', "password")
        except:
            encryptedInfo = data.get("PacketData", "encryptedInfo")

            encryptedLoginData = encryptedInfo.replace("Ciyvab0tregdVsBtboIpeChe4G6uzC1v5_-SIxmvSL", "")
            encryptedLoginData = encryptedLoginData.replace("-", "=").replace("_", "=")  # Bring string into proper format again

            loginData = b64decode(encryptedLoginData).split('\f')

            nuid = loginData[0]
            password = loginData[1]

        try:
            serverPassword = self.CONNOBJ.validServers[nuid]['password']

            if serverPassword == password:
                loginStatus = True
            else:
                loginStatus = "INCORRECT_PASSWORD"
        except:
            self.logger.error("[Login] Server wanted to login with incorrect login data!", 1)
            loginStatus = False

        if loginStatus:
            self.CONNOBJ.accountSessionKey = GenerateRandomString(27) + "."
            self.CONNOBJ.userID = self.CONNOBJ.validServers[nuid]['id']
            self.CONNOBJ.nuid = nuid

            toSend.set("PacketData", "lkey", self.CONNOBJ.accountSessionKey)
            toSend.set("PacketData", "nuid", nuid)

            if returnEncryptedInfo == 1:
                encryptedLoginData = "Ciyvab0tregdVsBtboIpeChe4G6uzC1v5_-SIxmvSL"
                encryptedLoginData += GenerateRandomString(86)

                toSend.set("PacketData", "encryptedLoginInfo", encryptedLoginData)

            toSend.set("PacketData", "profileId", str(self.CONNOBJ.userID))
            toSend.set("PacketData", "userId", str(self.CONNOBJ.userID))

            self.logger.notification("[Login] Server " + nuid + " logged in successfully!", 1)
        elif loginStatus == "INCORRECT_PASSWORD":  # The password the user specified is incorrect
            toSend.set("PacketData", "localizedMessage", "The password the user specified is incorrect")
            toSend.set("PacketData", "errorContainer.[]", "0")
            toSend.set("PacketData", "errorCode", "122")

            self.logger.warning("[Login] Server " + nuid + " specified incorrect password!", 1)
        else:  # User not found
            toSend.set("PacketData", "localizedMessage", "The user was not found")
            toSend.set("PacketData", "errorContainer.[]", "0")
            toSend.set("PacketData", "errorCode", "101")

            self.logger.error("[Login] Server " + nuid + " does not exist", 1)

        Packet(toSend).send(self, "acct", 0x80000000, self.CONNOBJ.plasmaPacketID)
    elif txn == 'NuGetPersonas':
        """ Get personas associated with account """

        toSend.set("PacketData", "TXN", "NuGetPersonas")
        toSend.set("PacketData", "personas.[]", "1")

        userID = self.CONNOBJ.userID

        if userID == 1:
            toSend.set("PacketData", "personas.0", "bfbc2.server.p")
        elif userID == 2:
            toSend.set("PacketData", "personas.0", "bfbc.server.ps")
        elif userID == 3:
            toSend.set("PacketData", "personas.0", "bfbc.server.xe")

        Packet(toSend).send(self, "acct", 0x80000000, self.CONNOBJ.plasmaPacketID)
    elif txn == 'NuLoginPersona':
        toSend = Packet().create()
        toSend.set("PacketData", "TXN", "NuLoginPersona")

        requestedPersonaName = data.get("PacketData", "name")

        if requestedPersonaName in self.CONNOBJ.validPersonas:
            self.CONNOBJ.personaID = self.CONNOBJ.validPersonas[requestedPersonaName]
            self.CONNOBJ.personaSessionKey = GenerateRandomString(27) + "."
            self.CONNOBJ.personaName = requestedPersonaName

            toSend.set("PacketData", "lkey", self.CONNOBJ.personaSessionKey)
            toSend.set("PacketData", "profileId", str(self.CONNOBJ.personaID))
            toSend.set("PacketData", "userId", str(self.CONNOBJ.personaID))

            self.logger.notification("[Persona] Server " + self.CONNOBJ.nuid + " just logged as " + requestedPersonaName, 1)
        else:
            toSend.set("PacketData", "localizedMessage", "The user was not found")
            toSend.set("PacketData", "errorContainer.[]", "0")
            toSend.set("PacketData", "errorCode", "101")
            self.logger.error("[Persona] Server " + self.CONNOBJ.nuid + " wanted to login as " + requestedPersonaName + " but this persona cannot be found!", 1)

        Packet(toSend).send(self, "acct", 0x80000000, self.CONNOBJ.plasmaPacketID)
    elif txn == 'NuGetEntitlements':
        toSend.set("PacketData", "TXN", "NuGetEntitlements")

        playerUserId = data.get("PacketData", "masterUserId")
        personaID = 0
        for player in Clients:
            if player.userID == int(playerUserId):
                personaID = player.personaID
                break

        try:
            groupName = data.get("PacketData", "groupName")
        except:
            groupName = None

        userEntitlements = db.getUserEntitlements(playerUserId)
        entitlements = []
        if personaID != 0:
            if groupName is not None:
                for entitlement in userEntitlements:
                    if entitlement['groupName'] == groupName:
                        entitlements.append(entitlement)

                count = 0
                for entitlement in entitlements:
                    toSend.set("PacketData", "entitlements." + str(count) + ".grantDate", entitlement['grantDate'])
                    toSend.set("PacketData", "entitlements." + str(count) + ".groupName", entitlement['groupName'])
                    toSend.set("PacketData", "entitlements." + str(count) + ".userId", entitlement['userId'])
                    toSend.set("PacketData", "entitlements." + str(count) + ".entitlementTag",
                               entitlement['entitlementTag'])
                    toSend.set("PacketData", "entitlements." + str(count) + ".version", entitlement['version'])
                    toSend.set("PacketData", "entitlements." + str(count) + ".terminationDate",
                               entitlement['terminationDate'])
                    toSend.set("PacketData", "entitlements." + str(count) + ".productId", entitlement['productId'])
                    toSend.set("PacketData", "entitlements." + str(count) + ".entitlementId",
                               entitlement['entitlementId'])
                    toSend.set("PacketData", "entitlements." + str(count) + ".status", entitlement['status'])
                    toSend.set("PacketData", "entitlements." + str(count) + ".statusReasonCode",
                               entitlement['statusReasonCode'])
                    count += 1
            else:
                try:
                    entitlementTag = data.get("PacketData", "entitlementTag")
                except:
                    entitlementTag = None

                try:
                    projectId = str(data.get("PacketData", "projectId"))
                except:
                    projectId = None

                if entitlementTag == "BFBC2:PC:VIETNAM_ACCESS":
                    for entitlement in userEntitlements:
                        if entitlement['groupName'] == groupName:
                            entitlements.append(entitlement)

                    count = 0
                    for entitlement in entitlements:
                        toSend.set("PacketData", "entitlements." + str(count) + ".grantDate", entitlement['grantDate'])
                        toSend.set("PacketData", "entitlements." + str(count) + ".groupName", entitlement['groupName'])
                        toSend.set("PacketData", "entitlements." + str(count) + ".userId", entitlement['userId'])
                        toSend.set("PacketData", "entitlements." + str(count) + ".entitlementTag",
                                   entitlement['entitlementTag'])
                        toSend.set("PacketData", "entitlements." + str(count) + ".version", entitlement['version'])
                        toSend.set("PacketData", "entitlements." + str(count) + ".terminationDate",
                                   entitlement['terminationDate'])
                        toSend.set("PacketData", "entitlements." + str(count) + ".productId", entitlement['productId'])
                        toSend.set("PacketData", "entitlements." + str(count) + ".entitlementId",
                                   entitlement['entitlementId'])
                        toSend.set("PacketData", "entitlements." + str(count) + ".status", entitlement['status'])
                        toSend.set("PacketData", "entitlements." + str(count) + ".statusReasonCode",
                                   entitlement['statusReasonCode'])
                        count += 1

                if projectId == "136844":
                    for entitlement in userEntitlements:
                        if entitlement['entitlementTag'] == 'BFBC2NAM%3aPC%3aNOVETRANK':
                            entitlements.append(entitlement)
                        elif entitlement['entitlementTag'] == 'ONLINE_ACCESS':
                            entitlements.append(entitlement)
                        elif entitlement['entitlementTag'] == 'BFBC2%3aPC%3aADDSVETRANK':
                            entitlements.append(entitlement)
                        elif entitlement['entitlementTag'] == 'BETA_ONLINE_ACCESS':
                            entitlements.append(entitlement)
                        elif entitlement['entitlementTag'] == 'BFBC2%3aPC%3aLimitedEdition':
                            entitlements.append(entitlement)

                        count = 0
                        for entitlement in entitlements:
                            toSend.set("PacketData", "entitlements." + str(count) + ".grantDate",
                                       entitlement['grantDate'])
                            toSend.set("PacketData", "entitlements." + str(count) + ".groupName",
                                       entitlement['groupName'])
                            toSend.set("PacketData", "entitlements." + str(count) + ".userId", entitlement['userId'])
                            toSend.set("PacketData", "entitlements." + str(count) + ".entitlementTag",
                                       entitlement['entitlementTag'])
                            toSend.set("PacketData", "entitlements." + str(count) + ".version", entitlement['version'])
                            toSend.set("PacketData", "entitlements." + str(count) + ".terminationDate",
                                       entitlement['terminationDate'])
                            toSend.set("PacketData", "entitlements." + str(count) + ".productId",
                                       entitlement['productId'])
                            toSend.set("PacketData", "entitlements." + str(count) + ".entitlementId",
                                       entitlement['entitlementId'])
                            toSend.set("PacketData", "entitlements." + str(count) + ".status", entitlement['status'])
                            toSend.set("PacketData", "entitlements." + str(count) + ".statusReasonCode",
                                       entitlement['statusReasonCode'])
                            count += 1

                if projectId == "302061":
                    for entitlement in userEntitlements:
                        if entitlement['entitlementTag'] == 'BFBC2%3aPC%3aALLKIT':
                            entitlements.append(entitlement)

                        count = 0
                        for entitlement in entitlements:
                            toSend.set("PacketData", "entitlements." + str(count) + ".grantDate",
                                       entitlement['grantDate'])
                            toSend.set("PacketData", "entitlements." + str(count) + ".groupName",
                                       entitlement['groupName'])
                            toSend.set("PacketData", "entitlements." + str(count) + ".userId", entitlement['userId'])
                            toSend.set("PacketData", "entitlements." + str(count) + ".entitlementTag",
                                       entitlement['entitlementTag'])
                            toSend.set("PacketData", "entitlements." + str(count) + ".version", entitlement['version'])
                            toSend.set("PacketData", "entitlements." + str(count) + ".terminationDate",
                                       entitlement['terminationDate'])
                            toSend.set("PacketData", "entitlements." + str(count) + ".productId",
                                       entitlement['productId'])
                            toSend.set("PacketData", "entitlements." + str(count) + ".entitlementId",
                                       entitlement['entitlementId'])
                            toSend.set("PacketData", "entitlements." + str(count) + ".status", entitlement['status'])
                            toSend.set("PacketData", "entitlements." + str(count) + ".statusReasonCode",
                                       entitlement['statusReasonCode'])
                            count += 1

        toSend.set("PacketData", "entitlements.[]", str(len(entitlements)))

        Packet(toSend).send(self, "acct", 0x80000000, self.CONNOBJ.plasmaPacketID)
    elif txn == 'NuLookupUserInfo':
        toSend.set("PacketData", "TXN", "NuLookupUserInfo")

        personaName = data.get("PacketData", "userInfo.0.userName")
        personaData = db.getPersonaInfo(personaName)

        if personaData is not False:
            toSend.set("PacketData", "userInfo.[]", "1")
            toSend.set("PacketData", "userInfo.0.userName", str(personaData['personaName']))
            toSend.set("PacketData", "userInfo.0.namespace", "battlefield")
            toSend.set("PacketData", "userInfo.0.userId", str(personaData['personaID']))
            toSend.set("PacketData", "userInfo.0.masterUserId", str(personaData['userID']))
        else:
            toSend.set("PacketData", "userInfo.[]", "1")
            toSend.set("PacketData", "userInfo.0.userName", personaName)

        Packet(toSend).send(self, "acct", 0x80000000, self.CONNOBJ.plasmaPacketID)
    else:
        self.logger.error("[" + self.ip + ":" + str(self.port) + ']<-- Got unknown acct message (' + txn + ")", 2)
        self.send_error_packet("acct", txn)


def asso(self, data, txn):
    toSend = Packet().create()

    if txn == "GetAssociations":
        toSend.set("PacketData", "TXN", "GetAssociations")

        type = data.get("PacketData", "type")

        toSend.set("PacketData", "domainPartition.domain", data.get("PacketData", "domainPartition.domain"))
        toSend.set("PacketData", "domainPartition.subDomain", data.get("PacketData", "domainPartition.subDomain"))
        toSend.set("PacketData", "owner.id", str(self.CONNOBJ.personaID))
        toSend.set("PacketData", "owner.type", "1")
        toSend.set("PacketData", "type", type)
        toSend.set("PacketData", "members.[]", "0")

        if type == "PlasmaMute":
            toSend.set("PacketData", "maxListSize", "20")
            toSend.set("PacketData", "owner.name", self.CONNOBJ.personaName)
        elif type == 'PlasmaBlock':
            toSend.set("PacketData", "maxListSize", "20")
            toSend.set("PacketData", "owner.name", self.CONNOBJ.personaName)
        elif type == 'PlasmaFriends':
            toSend.set("PacketData", "maxListSize", "20")
            toSend.set("PacketData", "owner.name", self.CONNOBJ.personaName)
        elif type == 'PlasmaRecentPlayers':
            toSend.set("PacketData", "maxListSize", "100")
        elif type == 'dogtags':
            toSend.set("PacketData", "maxListSize", "20")
            toSend.set("PacketData", "owner.name", self.CONNOBJ.personaName)

        Packet(toSend).send(self, "asso", 0x80000000, self.CONNOBJ.plasmaPacketID)
    elif txn == "AddAssociations":
        toSend.set("PacketData", "TXN", "AddAssociations")

        type = data.get("PacketData", "type")

        toSend.set("PacketData", "domainPartition.domain", data.get("PacketData", "domainPartition.domain"))
        toSend.set("PacketData", "domainPartition.subDomain", data.get("PacketData", "domainPartition.subDomain"))
        toSend.set("PacketData", "type", type)
        toSend.set("PacketData", "result.[]", "0")

        if type == 'PlasmaRecentPlayers':
            toSend.set("PacketData", "maxListSize", "100")

        Packet(toSend).send(self, "asso", 0x80000000, self.CONNOBJ.plasmaPacketID)
    else:
        self.logger.error("[" + self.ip + ":" + str(self.port) + ']<-- Got unknown asso message (' + txn + ")", 2)
        self.send_error_packet("asso", txn)


def rank(self, data, txn):
    toSend = Packet().create()

    if txn == 'GetStats':
        toSend.set("PacketData", "TXN", "GetStats")

        requestedKeysNumber = int(data.get("PacketData", "keys.[]"))

        for i in range(requestedKeysNumber):
            requestedKey = data.get("PacketData", "keys." + str(i))

            toSend.set("PacketData", "stats." + str(i) + ".key", requestedKey)
            toSend.set("PacketData", "stats." + str(i) + ".value", "0.0")  # Until i won't do database for stats - it'll always return 0.0

        toSend.set("PacketData", "stats.[]", str(requestedKeysNumber))

        Packet(toSend).send(self, "rank", 0x80000000, self.CONNOBJ.plasmaPacketID)
    else:
        self.logger.error("[" + self.ip + ":" + str(self.port) + ']<-- Got unknown rank message (' + txn + ")", 2)
        self.send_error_packet("rank", txn)


def CGAM(self, data):
    """ Create Game """

    toSend = Packet().create()
    toSend.set("PacketData", "TID", str(data.get("PacketData", "TID")))

    self.CONNOBJ.serverData = ConfigParser()
    self.CONNOBJ.serverData.optionxform = str
    self.CONNOBJ.serverData.add_section("ServerData")

    for item in data.items("PacketData"):
        if item[0] != "TID":
            self.CONNOBJ.serverData.set("ServerData", item[0], str(item[1]).replace('"', ""))

    toSend.set("PacketData", "MAX-PLAYERS", str(data.get("PacketData", "MAX-PLAYERS")))
    toSend.set("PacketData", "EKEY", "AIBSgPFqRDg0TfdXW1zUGa4%3d")
    toSend.set("PacketData", "UGID", str(data.get("PacketData", "UGID")))
    toSend.set("PacketData", "JOIN", str(data.get("PacketData", "JOIN")))

    if len(data.get("PacketData", "SECRET")) != 0:
        toSend.set("PacketData", "SECRET", data.get("PacketData", "SECRET"))
    else:
        toSend.set("PacketData", "SECRET", "4l94N6Y0A3Il3+kb55pVfK6xRjc+Z6sGNuztPeNGwN5CMwC7ZlE/lwel07yciyZ5y3bav7whbzHugPm11NfuBg%3d%3d")

    toSend.set("PacketData", "LID", "1")
    toSend.set("PacketData", "J", str(data.get("PacketData", "JOIN")))
    toSend.set("PacketData", "GID", str(self.CONNOBJ.gameID))

    Packet(toSend).send(self, "CGAM", 0x00000000, 0)

    self.logger.notification("[" + self.ip + ":" + str(self.port) + "] Created new game!", 1)


def UBRA(self, data):
    if data.get("PacketData", "START") == "1":
        self.CONNOBJ.startedUBRAs += 2
    else:
        orig_tid = int(data.get("PacketData", "TID")) - self.CONNOBJ.startedUBRAs / 2

        for packet in range(self.CONNOBJ.startedUBRAs):
            toSend = Packet().create()
            toSend.set("PacketData", "TID", str(orig_tid + packet))

            Packet(toSend).send(self, "UBRA", 0x00000000, 0)
            self.CONNOBJ.startedUBRAs -= 1


def UGAM(self, data):
    """ Update server info """

    for item in data.items("PacketData"):
        if item[0] != "TID":
            self.CONNOBJ.serverData.set("ServerData", item[0], str(item[1]).replace('"', ""))

    self.logger.notification("[" + self.ip + ":" + str(self.port) + "] Updated server info!")


def UGDE(self, data):
    """ Update game info """

    for item in data.items("PacketData"):
        if item[0] != "TID":
            self.CONNOBJ.serverData.set("ServerData", item[0], str(item[1]).replace('"', ""))

    self.logger.notification("[" + self.ip + ":" + str(self.port) + "] Updated game info!")


def EGRS(self, data):
    toSend = Packet().create()

    allowed = data.get("PacketData", "ALLOWED")

    if str(allowed) == "1":
        self.CONNOBJ.joiningPlayers += 1

    toSend.set("PacketData", "TID", str(data.get("PacketData", "TID")))
    Packet(toSend).send(self, "EGRS", 0x00000000, 0)


def PENT(self, data):
    self.CONNOBJ.joiningPlayers -= 1
    self.CONNOBJ.activePlayers += 1

    toSend = Packet().create()
    toSend.set("PacketData", "TID", str(data.get("PacketData", "TID")))
    toSend.set("PacketData", "PID", str(data.get("PacketData", "PID")))

    Packet(toSend).send(self, "PENT", 0x00000000, 0)


def PLVT(self, data):
    playerID = str(data.get("PacketData", "PID"))
    lobbyID = str(data.get("PacketData", "LID"))
    gameID = str(data.get("PacketData", "GID"))

    toSend = Packet().create()
    toSend.set("PacketData", "PID", playerID)
    toSend.set("PacketData", "LID", lobbyID)
    toSend.set("PacketData", "GID", gameID)
    Packet(toSend).send(self, "KICK", 0x00000000, 0)

    self.CONNOBJ.activePlayers -= 1
    for player in range(len(self.CONNOBJ.connectedPlayers)):
        if int(playerID) == self.CONNOBJ.connectedPlayers[player].playerID:
            self.CONNOBJ.connectedPlayers[player].playerID = 0
            del self.CONNOBJ.connectedPlayers[player]

    toSend = Packet().create()
    toSend.set("PacketData", "TID", str(data.get("PacketData", "TID")))
    Packet(toSend).send(self, "PLVT", 0x00000000, 0)
