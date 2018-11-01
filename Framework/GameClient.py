# -*- coding: utf-8 -*-

import re
from base64 import b64decode, b64encode
from datetime import datetime

from Config import readFromConfig
from Database import Database
from Globals import Servers
from Utilities.Packet import Packet

from os.path import exists
from urllib import quote

from Utilities.RandomStringGenerator import GenerateRandomString

db = Database()


def acct(self, data, txn):
    toSend = Packet().create()

    if txn == 'GetCountryList':
        """ User wants to create a new account """

        if exists("Data/countryLists/countryList_" + self.CONNOBJ.locale):
            with open("Data/countryLists/countryList_" + self.CONNOBJ.locale) as countryListFile:
                countryListData = countryListFile.readlines()
        else:
            with open("Data/countryLists/default") as countryListFile:
                countryListData = countryListFile.readlines()

        toSend.set("PacketData", "TXN", "GetCountryList")
        toSend.set("PacketData", "countryList.[]", str(len(countryListData)))

        countryId = 0
        for line in countryListData:
            toSend.set("PacketData", "countryList." + str(countryId) + ".ISOCode", line.split("=")[0])
            toSend.set("PacketData", "countryList." + str(countryId) + ".description",
                       line.split("=")[1].replace('"', "").replace("\n", ""))
            countryId += 1

        Packet(toSend).send(self, "acct", 0x80000000, self.CONNOBJ.plasmaPacketID)
    elif txn == 'NuGetTos':
        """ Get Terms of Use """

        toSend.set("PacketData", "TXN", "NuGetTos")
        toSend.set("PacketData", "version", "20426_17.20426_17")

        if exists("Data/termsOfUse/termsOfUse_" + self.CONNOBJ.locale):
            with open("Data/termsOfUse/termsOfUse_" + self.CONNOBJ.locale) as termsOfUseFile:
                termsOfUse = termsOfUseFile.read()
        else:
            with open("Data/termsOfUse/default") as termsOfUseFile:
                termsOfUse = termsOfUseFile.read()

        termsOfUse = quote(termsOfUse, safe=" ,.'&/()?;®@§[]").replace("%3A", "%3a").replace("%0A", "%0a") + \
                     "%0a%0a%09Battlefield%3a Bad Company 2 Master Server Emulator by B1naryKill3r%0a" + \
                     "https://github.com/B1naryKill3r/BFBC2_MasterServer"

        toSend.set("PacketData", "tos", termsOfUse)

        Packet(toSend).send(self, "acct", 0x80000000, self.CONNOBJ.plasmaPacketID)
    elif txn == 'NuAddAccount':
        """ Final add account request (with data like email, password...) """

        toSend.set("PacketData", "TXN", "NuAddAccount")

        nuid = data.get('PacketData', 'nuid')  # Email
        password = data.get('PacketData', 'password')  # Password

        bd_Day = data.get('PacketData', 'DOBDay')
        bd_Month = data.get('PacketData', 'DOBMonth')
        bd_Year = data.get('PacketData', 'DOBYear')
        birthday = datetime.strptime(bd_Day + " " + bd_Month + " " + bd_Year, "%d %m %Y")
        timeNow = datetime.now()

        country = data.get('PacketData', 'country')

        if len(nuid) > 32 or len(nuid) < 3:  # Entered user name length is out of bounds
            toSend.set("PacketData", "errorContainer.[]", "1")
            toSend.set("PacketData", "errorCode", "21")
            toSend.set("PacketData", "localizedMessage", 'The required parameters for this call are missing or invalid')
            toSend.set("PacketData", "errorContainer.0.fieldName", "displayName")

            if len(nuid) > 32:
                toSend.set("PacketData", "errorContainer.0.fieldError", "3")
                toSend.set("PacketData", "errorContainer.0.value", "TOO_LONG")
                self.logger.warning("[Register] Email " + nuid + " is too long!", 1)
            else:
                toSend.set("PacketData", "errorContainer.0.fieldError", "2")
                toSend.set("PacketData", "errorContainer.0.value", "TOO_SHORT")
                self.logger.warning("[Register] Email " + nuid + " is too short!", 1)
        elif db.checkIfEmailTaken(nuid):  # Email is already taken
            toSend.set("PacketData", "errorContainer.[]", "0")
            toSend.set("PacketData", "errorCode", "160")
            toSend.set("PacketData", "localizedMessage", 'That account name is already taken')
            self.logger.error("[Register] User with email " + nuid + " is already registered!", 1)
        elif timeNow.year - birthday.year - (
                (timeNow.month, timeNow.day) < (birthday.month, birthday.day)) < 18:  # New user is not old enough
            toSend.set("PacketData", "errorContainer.[]", "1")
            toSend.set("PacketData", "errorContainer.0.fieldName", "dob")
            toSend.set("PacketData", "errorContainer.0.fieldError", "15")
            toSend.set("PacketData", "errorCode", "21")
            self.logger.warning("[Register] User with email " + nuid + " is too young to register new account!", 1)
        elif len(password) > 16:
            toSend.set("PacketData", "errorContainer.[]", "1")
            toSend.set("PacketData", "errorCode", "21")
            toSend.set("PacketData", "localizedMessage", 'The required parameters for this call are missing or invalid')
            toSend.set("PacketData", "errorContainer.0.fieldName", "displayName")
            toSend.set("PacketData", "errorContainer.0.fieldError", "3")
            toSend.set("PacketData", "errorContainer.0.value", "TOO_LONG")
            self.logger.warning("[Register] Password for user " + nuid + " is too long!", 1)
        elif bool(re.match("^[a-zA-Z0-9]+$", password)) is None:
            toSend.set("PacketData", "errorContainer.[]", "1")
            toSend.set("PacketData", "errorCode", "21")
            toSend.set("PacketData", "localizedMessage", 'The required parameters for this call are missing or invalid')
            toSend.set("PacketData", "errorContainer.0.fieldName", "displayName")
            toSend.set("PacketData", "errorContainer.0.fieldError", "6")
            toSend.set("PacketData", "errorContainer.0.value", "NOT_ALLOWED")
            self.logger.warning("[Register] Password for user " + nuid + " contains illegal characters!", 1)
        else:
            db.registerUser(nuid, password, str(birthday).split(" ")[0], country)
            self.logger.notification("[Register] User " + nuid + " was registered successfully!", 1)

        Packet(toSend).send(self, "acct", 0x80000000, self.CONNOBJ.plasmaPacketID)
    elif txn == 'NuLogin':
        """ User is logging in with email and password """

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

        loginData = db.loginUser(nuid, password)

        if loginData['UserID'] > 0:  # Got UserID - Login Successful
            self.CONNOBJ.accountSessionKey = loginData['SessionID']
            self.CONNOBJ.userID = loginData['UserID']
            self.CONNOBJ.nuid = nuid

            toSend.set("PacketData", "lkey", loginData['SessionID'])
            toSend.set("PacketData", "nuid", nuid)

            if returnEncryptedInfo == 1:
                encryptedLoginData = "Ciyvab0tregdVsBtboIpeChe4G6uzC1v5_-SIxmvSL" + b64encode(nuid + "\f" + password)

                if encryptedLoginData.find('==') != -1:
                    encryptedLoginData = encryptedLoginData.replace("==", '-_')
                else:
                    encryptedLoginData = encryptedLoginData.replace("=", '-')

                toSend.set("PacketData", "encryptedLoginInfo", encryptedLoginData)

            toSend.set("PacketData", "profileId", str(loginData['UserID']))
            toSend.set("PacketData", "userId", str(loginData['UserID']))

            self.logger.notification("[Login] User " + nuid + " logged in successfully!", 1)
        elif loginData['UserID'] == 0:  # The password the user specified is incorrect
            toSend.set("PacketData", "localizedMessage", "The password the user specified is incorrect")
            toSend.set("PacketData", "errorContainer.[]", "0")
            toSend.set("PacketData", "errorCode", "122")

            self.logger.warning("[Login] User " + nuid + " specified incorrect password!", 1)
        else:  # User not found
            toSend.set("PacketData", "localizedMessage", "The user was not found")
            toSend.set("PacketData", "errorContainer.[]", "0")
            toSend.set("PacketData", "errorCode", "101")

            self.logger.error("[Login] User " + nuid + " does not exist", 1)

        Packet(toSend).send(self, "acct", 0x80000000, self.CONNOBJ.plasmaPacketID)
    elif txn == 'NuGetPersonas':
        """ Get personas associated with account """

        userID = self.CONNOBJ.userID
        personas = db.getUserPersonas(userID)

        toSend.set("PacketData", "TXN", "NuGetPersonas")
        toSend.set("PacketData", "personas.[]", str(len(personas)))

        personaId = 0
        for persona in personas:
            toSend.set("PacketData", "personas." + str(personaId), persona)
            personaId += 1

        Packet(toSend).send(self, "acct", 0x80000000, self.CONNOBJ.plasmaPacketID)
    elif txn == 'NuLoginPersona':
        """ User logs in with selected Persona """

        toSend.set("PacketData", "TXN", "NuLoginPersona")

        requestedPersonaName = data.get("PacketData", "name")

        personaData = db.loginPersona(self.CONNOBJ.userID, requestedPersonaName)
        if personaData is not None:
            self.CONNOBJ.personaID = personaData['personaId']
            self.CONNOBJ.personaSessionKey = personaData['lkey']
            self.CONNOBJ.personaName = requestedPersonaName

            toSend.set("PacketData", "lkey", personaData['lkey'])
            toSend.set("PacketData", "profileId", str(self.CONNOBJ.personaID))
            toSend.set("PacketData", "userId", str(self.CONNOBJ.personaID))

            self.logger.notification("[Persona] User " + self.CONNOBJ.nuid + " just logged as " + requestedPersonaName, 1)
        else:
            toSend.set("PacketData", "localizedMessage", "The user was not found")
            toSend.set("PacketData", "errorContainer.[]", "0")
            toSend.set("PacketData", "errorCode", "101")
            self.logger.error("[Persona] User " + self.CONNOBJ.nuid + " wanted to login as " + requestedPersonaName + " but this persona cannot be found!", 1)

        Packet(toSend).send(self, "acct", 0x80000000, self.CONNOBJ.plasmaPacketID)
    elif txn == 'NuAddPersona':
        """ User wants to add a Persona """

        name = data.get("PacketData", "name")

        toSend.set("PacketData", "TXN", "NuAddPersona")

        if len(name) > 16 or len(name) < 3:  # Entered persona name length is out of bounds
            toSend.set("PacketData", "errorContainer.[]", "1")
            toSend.set("PacketData", "errorCode", "21")
            toSend.set("PacketData", "localizedMessage", "The required parameters for this call are missing or invalid")
            toSend.set("PacketData", "errorContainer.0.fieldName", "displayName")

            if len(name) > 16:
                toSend.set("PacketData", "errorContainer.0.fieldError", "3")
                toSend.set("PacketData", "errorContainer.0.value", "TOO_LONG")

                self.logger.warning("[Persona] User " + self.CONNOBJ.nuid + " wanted to create new persona, but name " + name + " is too long!", 1)
            else:
                toSend.set("PacketData", "errorContainer.0.fieldError", "2")
                toSend.set("PacketData", "errorContainer.0.value", "TOO_SHORT")

                self.logger.warning("[Persona] User " + self.CONNOBJ.nuid + " wanted to create new persona, but name " + name + " is too short!", 1)
        elif db.getPersonaInfo(name):  # Persona name has to be unique
            toSend.set("PacketData", "errorContainer.[]", "0")
            toSend.set("PacketData", "localizedMessage", "That account name is already taken")
            toSend.set("PacketData", "errorCode", "160")

            self.logger.error("[Persona] User " + self.CONNOBJ.nuid + " wanted to create new persona (" + name + "), but persona with this name is already registered in this account!", 1)
        elif bool(re.match("^[a-zA-Z0-9_\-&()*+./:;<=>?\[\]^{|}~]+$", name)) is False:
            toSend.set("PacketData", "errorContainer.[]", "1")
            toSend.set("PacketData", "errorCode", "21")
            toSend.set("PacketData", "localizedMessage", 'The required parameters for this call are missing or invalid')
            toSend.set("PacketData", "errorContainer.0.fieldName", "displayName")
            toSend.set("PacketData", "errorContainer.0.fieldError", "6")
            toSend.set("PacketData", "errorContainer.0.value", "NOT_ALLOWED")
        else:
            db.addPersona(self.CONNOBJ.userID, name)

            self.logger.notification("[Persona] User " + self.CONNOBJ.nuid + " just created new persona (" + name + ")", 1)

        Packet(toSend).send(self, "acct", 0x80000000, self.CONNOBJ.plasmaPacketID)
    elif txn == 'NuDisablePersona':
        """ User wants to remove a Persona """

        toSend.set("PacketData", "TXN", "NuDisablePersona")

        personaToDisable = data.get("PacketData", "name")

        if db.getPersonaInfo(personaToDisable):
            db.removePersona(self.CONNOBJ.userID, personaToDisable)

            self.logger.notification("[Persona] User " + self.CONNOBJ.nuid + " just removed persona (" + personaToDisable + ")", 1)
        else:
            toSend.set("PacketData", "localizedMessage", "The data necessary for this transaction was not found")
            toSend.set("PacketData", "errorContainer.[]", "0")
            toSend.set("PacketData", "errorCode", "104")
            self.logger.error("[Persona] User " + self.CONNOBJ.nuid + " wanted to remove persona (" + personaToDisable + "), but persona with this name didn't exist!", 1)

        Packet(toSend).send(self, "acct", 0x80000000, self.CONNOBJ.plasmaPacketID)
    elif txn == 'GetTelemetryToken':
        toSend.set("PacketData", "TXN", "GetTelemetryToken")

        tokenbuffer = readFromConfig("emulator", "emulator_ip")  # Messenger IP
        tokenbuffer += ","
        tokenbuffer += str(0)  # Messenger Port
        tokenbuffer += u",enUS,^Ů™¨Üś·Ć¤¤‰“ťĘ˙…Ź˛ŃĂÖ¬Ś±ďÄ±ˇ‚†Ś˛°ÄÝ±–†Ě›áî°ˇ‚†Ś°ŕŔ†Ě˛ąĘ‰»¦–Ĺ‚ťŠÔ©Ń©Ż„™’´ČŚ–±äŕł†Ś°îŔáŇĚŰŞÓ€"

        token = b64encode(tokenbuffer.encode("utf-8")).replace("=", "%3d")

        toSend.set("PacketData", "telemetryToken", token)
        toSend.set("PacketData", "enabled", "CA,MX,PR,US,VI,AD,AF,AG,AI,AL,AM,AN,AO,AQ,AR,AS,AW,AX,AZ,BA,BB,BD,BF,BH,BI,BJ,BM,BN,BO,BR,BS,BT,BV,BW,BY,BZ,CC,CD,CF,CG,CI,CK,CL,CM,CN,CO,CR,CU,CV,CX,DJ,DM,DO,DZ,EC,EG,EH,ER,ET,FJ,FK,FM,FO,GA,GD,GE,GF,GG,GH,GI,GL,GM,GN,GP,GQ,GS,GT,GU,GW,GY,HM,HN,HT,ID,IL,IM,IN,IO,IQ,IR,IS,JE,JM,JO,KE,KG,KH,KI,KM,KN,KP,KR,KW,KY,KZ,LA,LB,LC,LI,LK,LR,LS,LY,MA,MC,MD,ME,MG,MH,ML,MM,MN,MO,MP,MQ,MR,MS,MU,MV,MW,MY,MZ,NA,NC,NE,NF,NG,NI,NP,NR,NU,OM,PA,PE,PF,PG,PH,PK,PM,PN,PS,PW,PY,QA,RE,RS,RW,SA,SB,SC,clntSock,SG,SH,SJ,SL,SM,SN,SO,SR,ST,SV,SY,SZ,TC,TD,TF,TG,TH,TJ,TK,TL,TM,TN,TO,TT,TV,TZ,UA,UG,UM,UY,UZ,VA,VC,VE,VG,VN,VU,WF,WS,YE,YT,ZM,ZW,ZZ")
        toSend.set("PacketData", "filters", "")
        toSend.set("PacketData", "disabled", "")

        Packet(toSend).send(self, "acct", 0x80000000, self.CONNOBJ.plasmaPacketID)
    elif txn == 'NuGetEntitlements':
        toSend.set("PacketData", "TXN", "NuGetEntitlements")

        groupName = data.get("PacketData", "groupName")
        userID = self.CONNOBJ.userID

        userEntitlements = db.getUserEntitlements(userID)
        entitlements = []

        for entitlement in userEntitlements:
            if entitlement['groupName'] == groupName:
                entitlements.append(entitlement)

        count = 0
        for entitlement in entitlements:
            toSend.set("PacketData", "entitlements." + str(count) + ".grantDate", entitlement['grantDate'])
            toSend.set("PacketData", "entitlements." + str(count) + ".groupName", entitlement['groupName'])
            toSend.set("PacketData", "entitlements." + str(count) + ".userId", entitlement['userId'])
            toSend.set("PacketData", "entitlements." + str(count) + ".entitlementTag", entitlement['entitlementTag'])
            toSend.set("PacketData", "entitlements." + str(count) + ".version", entitlement['version'])
            toSend.set("PacketData", "entitlements." + str(count) + ".terminationDate", entitlement['terminationDate'])
            toSend.set("PacketData", "entitlements." + str(count) + ".productId", entitlement['productId'])
            toSend.set("PacketData", "entitlements." + str(count) + ".entitlementId", entitlement['entitlementId'])
            toSend.set("PacketData", "entitlements." + str(count) + ".status", entitlement['status'])
            toSend.set("PacketData", "entitlements." + str(count) + ".statusReasonCode",
                       entitlement['statusReasonCode'])
            count += 1

        toSend.set("PacketData", "entitlements.[]", str(len(entitlements)))

        Packet(toSend).send(self, "acct", 0x80000000, self.CONNOBJ.plasmaPacketID)
    elif txn == 'NuSearchOwners':
        toSend.set("PacketData", "TXN", "NuSearchOwners")
        toSend.set("PacketData", "nameSpaceId", "battlefield")

        screenName = data.get("PacketData", "screenName").replace("_", "")
        searchResults = db.searchPersonas(screenName)

        if len(searchResults) != 0:
            count = 0
            for user in searchResults:
                if user['UserID'] != self.CONNOBJ.userID:  # Prevent self-adding
                    toSend.set("PacketData", "users." + str(count) + ".id", str(user['PersonaID']))
                    toSend.set("PacketData", "users." + str(count) + ".name", user['PersonaName'])
                    toSend.set("PacketData", "users." + str(count) + ".type", "1")
                    count += 1

            toSend.set("PacketData", "users.[]", str(count))
        else:
            toSend.set("PacketData", "errorContainer.[]", "0")
            toSend.set("PacketData", "errorCode", "104")
            toSend.set("PacketData", "localizedMessage", "The data necessary for this transaction was not found")

        Packet(toSend).send(self, "acct", 0x80000000, self.CONNOBJ.plasmaPacketID)
    elif txn == 'GetLockerURL':
        toSend.set("PacketData", "TXN", "GetLockerURL")

        url = "http%3a//" + readFromConfig("emulator", "emulator_ip") + "/fileupload/locker2.jsp"

        toSend.set("PacketData", "URL", url)

        Packet(toSend).send(self, "acct", 0x80000000, self.CONNOBJ.plasmaPacketID)
    elif txn == 'NuLookupUserInfo':
        toSend.set("PacketData", "TXN", "NuLookupUserInfo")

        personaName = data.get("PacketData", "userInfo.0.userName")
        personaData = db.getPersonaInfo(personaName)

        if personaData is not False:
            toSend.set("PacketData", "userInfo.[]", "1")
            toSend.set("PacketData", "userInfo.0.userName", str(personaData['personaName']))
            toSend.set("PacketData", "userInfo.0.namespace", "battlefield")
            toSend.set("PacketData", "userInfo.0.userId", str(personaData['userID']))
            toSend.set("PacketData", "userInfo.0.masterUserId", str(personaData['personaID']))
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
        toSend.set("PacketData", "type", type)
        toSend.set("PacketData", "domainPartition.domain", data.get("PacketData", "domainPartition.domain"))
        toSend.set("PacketData", "domainPartition.subDomain", data.get("PacketData", "domainPartition.subDomain"))
        toSend.set("PacketData", "owner.id", str(self.CONNOBJ.personaID))
        toSend.set("PacketData", "owner.name", self.CONNOBJ.personaName)
        toSend.set("PacketData", "owner.type", "1")

        if type == "PlasmaMute":
            associations = db.getUserAssociations(self.CONNOBJ.personaID, 'MutedPlayers')
        elif type == 'PlasmaBlock':
            associations = db.getUserAssociations(self.CONNOBJ.personaID, 'BlockedPlayers')
        elif type == 'PlasmaFriends':
            associations = db.getUserAssociations(self.CONNOBJ.personaID, 'UsersFriends')
        elif type == 'PlasmaRecentPlayers':
            associations = db.getUserAssociations(self.CONNOBJ.personaID, 'RecentPlayers')
        else:
            associations = []

        if len(associations) > 0:
            toSend.set("PacketData", "maxListSize", str(100 * (len(associations) / 2)))
        else:
            toSend.set("PacketData", "maxListSize", "100")

        count = 0
        for association in associations:
            toSend.set("PacketData", "members." + str(count) + ".id", association['concernPersonaID'])
            toSend.set("PacketData", "members." + str(count) + ".name", association['concernPersonaName'])
            toSend.set("PacketData", "members." + str(count) + ".type", association['type'])
            toSend.set("PacketData", "members." + str(count) + ".created", association['creationDate'])
            toSend.set("PacketData", "members." + str(count) + ".modified", association['creationDate'])
        toSend.set("PacketData", "members.[]", str(len(associations)))

        Packet(toSend).send(self, "asso", 0x80000000, self.CONNOBJ.plasmaPacketID)
    elif txn == "AddAssociations":
        toSend.set("PacketData", "TXN", "AddAssociations")
        toSend.set("PacketData", "result.[]", "0")  # TODO: Check what to send when it's 1
        toSend.set("PacketData", "type", str(data.get("PacketData", "type")))
        toSend.set("PacketData", "domainPartition.domain", "eagames")
        toSend.set("PacketData", "domainPartition.subDomain", "BFBC2")
        toSend.set("PacketData", "maxListSize", "100")

        type = data.get("PacketData", "type")

        if type == 'PlasmaFriends':
            for request in range(int(data.get("PacketData", "addRequests.[]"))):
                ownerID = int(data.get("PacketData", "addRequests." + str(request) + ".owner.id"))
                ownerType = int(data.get("PacketData", "addRequests." + str(request) + ".owner.type"))
                memberID = int(data.get("PacketData", "addRequests." + str(request) + ".member.id"))

                db.AddAssociations(memberID, ownerID, ownerType, 'UsersFriends')

        Packet(toSend).send(self, "asso", 0x80000000, self.CONNOBJ.plasmaPacketID)
    else:
        self.logger.error("[" + self.ip + ":" + str(self.port) + ']<-- Got unknown asso message (' + txn + ")", 2)
        self.send_error_packet("asso", txn)


def xmsg(self, data, txn):
    toSend = Packet().create()

    if txn == 'ModifySettings':
        # TODO: Modify settings in database

        toSend.set("PacketData", "TXN", "ModifySettings")

        Packet(toSend).send(self, "xmsg", 0x80000000, self.CONNOBJ.plasmaPacketID)
    elif txn == 'GetMessages':
        toSend.set("PacketData", "TXN", "GetMessages")

        userMessages = db.getMessages(self.CONNOBJ.personaID)

        if len(userMessages) != 0:
            count = 0
            for message in userMessages:

                attachmentsDB = message['attachments'].split("|")
                attachmentCount = len(attachmentsDB) - 2  # Remove beginning and ending

                curMsg = 1
                attachments = []
                for attachment in range(attachmentCount):
                    attachments.append(attachmentsDB[curMsg].split(":"))
                    curMsg += 2

                attachmentCount = 0
                for attachment in attachments:
                    toSend.set("PacketData",
                               "messages." + str(count) + ".attachments." + str(attachmentCount) + ".type",
                               str(attachment[0]))
                    toSend.set("PacketData", "messages." + str(count) + ".attachments." + str(attachmentCount) + ".key",
                               str(attachment[1]))
                    toSend.set("PacketData",
                               "messages." + str(count) + ".attachments." + str(attachmentCount) + ".data",
                               '"' + str(attachment[2]) + '"')
                    attachmentCount += 1

                toSend.set("PacketData", "messages." + str(count) + ".attachments.[]", str(attachmentCount))

                toSend.set("PacketData", "messages." + str(count) + ".messageId", message['messageID'])
                toSend.set("PacketData", "messages." + str(count) + ".from.name", message['senderPersonaName'])
                toSend.set("PacketData", "messages." + str(count) + ".from.id", message['senderID'])

                toSend.set("PacketData", "messages." + str(count) + ".messageType", message['messageType'])
                toSend.set("PacketData", "messages." + str(count) + ".deliveryType", message['deliveryType'])
                toSend.set("PacketData", "messages." + str(count) + ".purgeStrategy", message['purgeStrategy'])
                toSend.set("PacketData", "messages." + str(count) + ".expiration", message['expiration'])
                toSend.set("PacketData", "messages." + str(count) + ".timeSent", message['timeSent'])

                #  Unknown things (why this are being send by original server?)
                toSend.set("PacketData", "messages." + str(count) + ".to.0.name", str(self.CONNOBJ.personaName))
                toSend.set("PacketData", "messages." + str(count) + ".to.0.id", str(self.CONNOBJ.personaID))
                toSend.set("PacketData", "messages." + str(count) + ".to.[]", "1")

                count += 1

        toSend.set("PacketData", "messages.[]", str(len(userMessages)))

        Packet(toSend).send(self, "xmsg", 0x80000000, self.CONNOBJ.plasmaPacketID)
    elif txn == 'SendMessage':
        toSend.set("PacketData", "TXN", "SendMessage")

        to = int(data.get("PacketData", "to.[]"))
        attachmentsCount = int(data.get("PacketData", "attachments.[]"))

        attachments = ""
        toUsers = []

        for i in range(to):
            toUsers.append(int(data.get("PacketData", "to." + str(i))))

        for i in range(attachmentsCount):
            attachments += "|" + data.get("PacketData", "attachments." + str(i) + ".type") + ":" + data.get(
                "PacketData", "attachments." + str(i) + ".key") + ":" + data.get("PacketData", "attachments." + str(
                i) + ".data") + "|"

        messageId = db.sendMessage(self.CONNOBJ.personaID, toUsers, data.get("PacketData", "messageType"), attachments,
                                   int(data.get("PacketData", "expires")), data.get("PacketData", "deliveryType"),
                                   data.get("PacketData", "purgeStrategy"))

        if messageId is not False:
            toSend.set('PacketData', 'messageId', str(messageId))
            toSend.set("PacketData", "status.[]", str(len(toUsers)))

            count = 0

            for user in toUsers:
                toSend.set("PacketData", "status." + str(count) + ".status", "1")
                toSend.set("PacketData", "status." + str(count) + ".userid", str(user))
        else:
            toSend.set('PacketData', 'messageId', "0")
            toSend.set("PacketData", "status.[]", str(len(toUsers)))

            count = 0

            for user in toUsers:
                toSend.set("PacketData", "status." + str(count) + ".status", "0")
                toSend.set("PacketData", "status." + str(count) + ".userid", str(user))

        Packet(toSend).send(self, "xmsg", 0x80000000, self.CONNOBJ.plasmaPacketID)
    elif txn == 'DeleteMessages':
        toSend.set("PacketData", "TXN", "DeleteMessages")

        messagesToDelete = int(data.get("PacketData", "messageIds.[]"))
        messageIds = []

        for message in range(messagesToDelete):
            messageIds.append(data.get("PacketData", "messageIds." + str(message)))

        db.deleteMessages(messageIds)

        Packet(toSend).send(self, "xmsg", 0x80000000, self.CONNOBJ.plasmaPacketID)
    else:
        self.logger.error("[" + self.ip + ":" + str(self.port) + ']<-- Got unknown xmsg message (' + txn + ")", 2)
        self.send_error_packet("xmsg", txn)


def pres(self, data, txn):
    toSend = Packet().create()

    if txn == "SetPresenceStatus":
        # TODO: Make the Presence Status database

        toSend = Packet().create()
        toSend.set("PacketData", "TXN", "SetPresenceStatus")

        Packet(toSend).send(self, "pres", 0x80000000, self.CONNOBJ.plasmaPacketID)
    else:
        self.logger.error("[" + self.ip + ":" + str(self.port) + ']<-- Got unknown pres message (' + txn + ")", 2)
        self.send_error_packet("pres", txn)


def rank(self, data, txn):
    toSend = Packet().create()

    if txn == 'GetStats':
        toSend.set("PacketData", "TXN", "GetStats")

        requestedKeysNumber = int(data.get("PacketData", "keys.[]"))
        requestedKeys = []

        for i in range(requestedKeysNumber):
            requestedKeys.append(data.get("PacketData", "keys." + str(i)))

        keysValues = db.GetStatsForPersona(self.CONNOBJ.personaID, requestedKeys)

        for i in range(len(requestedKeys)):
            toSend.set("PacketData", "stats." + str(i) + ".key", keysValues[i]['name'])
            toSend.set("PacketData", "stats." + str(i) + ".value", keysValues[i]['value'])

        toSend.set("PacketData", "stats.[]", str(requestedKeysNumber))

        Packet(toSend).send(self, "rank", 0x80000000, self.CONNOBJ.plasmaPacketID)
    else:
        self.logger.error("[" + self.ip + ":" + str(self.port) + ']<-- Got unknown rank message (' + txn + ")", 2)
        self.send_error_packet("rank", txn)


def recp(self, data, txn):
    toSend = Packet().create()

    if txn == 'GetRecordAsMap':
        """ Get all dogtags the persona possesses """
        # TODO: Make Dogtags database

        toSend.set("PacketData", "TXN", "GetRecordAsMap")
        toSend.set("PacketData", "TTL", "0")
        toSend.set("PacketData", "state", "1")
        toSend.set("PacketData", "values.{}", "0")

        Packet(toSend).send(self, "rank", 0x80000000, self.CONNOBJ.plasmaPacketID)
    elif txn == 'GetRecord':
        # TODO: find out what it is, and what to do with it

        toSend.set("PacketData", "TXN", "GetRecord")
        toSend.set("PacketData", "localizedMessage", "Record not found")
        toSend.set("PacketData", "errorContainer.[]", "0")
        toSend.set("PacketData", "errorCode", "5000")
        Packet(toSend).send(self, "rank", 0x80000000, self.CONNOBJ.plasmaPacketID)
    else:
        self.logger.error("[" + self.ip + ":" + str(self.port) + ']<-- Got unknown recp message (' + txn + ")", 2)
        self.send_error_packet("recp", txn)


def GDAT(self, data):
    try:
        lobbyID = str(data.get("PacketData", "LID"))
        gameID = str(data.get("PacketData", "GID"))
    except:
        lobbyID = None
        gameID = None

    if lobbyID is not None and gameID is not None:
        server = None

        for srv in Servers:
            if str(srv.serverData.get("ServerData", "LID")) == lobbyID and str(srv.serverData.get("ServerData", "GID")) == gameID:
                server = srv

        toSend = Packet().create()
        toSend.set("PacketData", "TID", str(data.get("PacketData", "TID")))
        toSend.set("PacketData", "LID", lobbyID)
        toSend.set("PacketData", "GID", gameID)

        toSend.set("PacketData", "HU", str(server.personaID))
        toSend.set("PacketData", "HN", str(server.personaName))

        toSend.set("PacketData", "I", server.ipAddr)
        toSend.set("PacketData", "P", str(server.serverData.get("ServerData", "PORT")))  # Port

        toSend.set("PacketData", "N", str(server.serverData.get("ServerData", "NAME")))  # name of server in list
        toSend.set("PacketData", "AP", str(server.activePlayers))  # current number of players on server
        toSend.set("PacketData", "MP", str(server.serverData.get("ServerData", "MAX-PLAYERS")))  # Maximum players on server
        toSend.set("PacketData", "QP", str(server.serverData.get("ServerData", "B-U-QueueLength")))  # Something with the queue...lets just set this equal to B-U-QueueLength
        toSend.set("PacketData", "JP", str(server.joiningPlayers))  # Players that are joining the server right now?
        toSend.set("PacketData", "PL", "PC")  # Platform - PC / XENON / PS3

        # Constants
        toSend.set("PacketData", "PW", "0")  # ??? - its certainly not something like "hasPassword"
        toSend.set("PacketData", "TYPE", str(server.serverData.get("ServerData", "TYPE")))  # what type?? constant value - "G"
        toSend.set("PacketData", "J", str(server.serverData.get("ServerData", "JOIN")))  # ??? constant value - "O"

        # Userdata
        toSend.set("PacketData", "B-U-Softcore", str(server.serverData.get("ServerData", "B-U-Softcore")))  # Game is softcore - what does that mean?
        toSend.set("PacketData", "B-U-Hardcore", str(server.serverData.get("ServerData", "B-U-Hardcore")))  # Game is hardcore
        toSend.set("PacketData", "B-U-HasPassword", str(server.serverData.get("ServerData", "B-U-HasPassword")))  # Game has password
        toSend.set("PacketData", "B-U-Punkbuster", str(server.serverData.get("ServerData", "B-U-Punkbuster")))  # Game has punkbuster?
        toSend.set("PacketData", "B-U-EA", str(server.serverData.get("ServerData", "B-U-EA")))  # is server EA Orginal?

        toSend.set("PacketData", "B-version", str(server.serverData.get("ServerData", "B-version")))  # Version of the server (exact version) - TRY TO CONNECT TO ACTUAL VERSION OF SERVER
        toSend.set("PacketData", "V", str(server.clientVersion))  # "clientVersion" of server (shows up in server log on startup)
        toSend.set("PacketData", "B-U-level", str(server.serverData.get("ServerData", "B-U-level")))  # current map of server
        toSend.set("PacketData", "B-U-gamemode", str(server.serverData.get("ServerData", "B-U-gamemode")))  # Gameplay Mode (Conquest, Rush, SQDM,  etc)
        toSend.set("PacketData", "B-U-sguid", str(server.serverData.get("ServerData", "B-U-sguid")))  # Game PB Server GUID?
        toSend.set("PacketData", "B-U-Time", str(server.serverData.get("ServerData", "B-U-Time")))  # uptime of server?
        toSend.set("PacketData", "B-U-hash", str(server.serverData.get("ServerData", "B-U-hash")))  # Game hash?
        toSend.set("PacketData", "B-U-region", str(server.serverData.get("ServerData", "B-U-region")))  # Game region
        toSend.set("PacketData", "B-U-public", str(server.serverData.get("ServerData", "B-U-public")))  # Game is public
        toSend.set("PacketData", "B-U-elo", str(server.serverData.get("ServerData", "B-U-elo")))  # value that determines how good the players on the server are?

        toSend.set("PacketData", "B-numObservers", str(server.serverData.get("ServerData", "B-numObservers")))  # Observers = spectators? or admins?
        toSend.set("PacketData", "B-maxObservers", str(server.serverData.get("ServerData", "B-maxObservers")))  # Game max observers
        toSend.set("PacketData", "B-U-Provider", str(server.serverData.get("ServerData", "B-U-Provider")))  # provider id, figured out by server
        toSend.set("PacketData", "B-U-gameMod", str(server.serverData.get("ServerData", "B-U-gameMod")))  # maybe different value for vietnam here?
        toSend.set("PacketData", "B-U-QueueLength", str(server.serverData.get("ServerData", "B-U-QueueLength")))  # players in queue or maximum queue length? (sometimes smaller than QP (-1?))
        Packet(toSend).send(self, "GDAT", 0x00000000, 0)

        toSend = Packet().create()
        toSend.set("PacketData", "TID", str(data.get("PacketData", "TID")))
        toSend.set("PacketData", "LID", lobbyID)
        toSend.set("PacketData", "GID", gameID)

        toSend.set("PacketData", "D-AutoBalance", server.serverData.get("ServerData", "D-AutoBalance"))
        toSend.set("PacketData", "D-Crosshair", server.serverData.get("ServerData", "D-Crosshair"))
        toSend.set("PacketData", "D-FriendlyFire", server.serverData.get("ServerData", "D-FriendlyFire"))
        toSend.set("PacketData", "D-KillCam", server.serverData.get("ServerData", "D-KillCam"))
        toSend.set("PacketData", "D-Minimap", server.serverData.get("ServerData", "D-Minimap"))
        toSend.set("PacketData", "D-MinimapSpotting", server.serverData.get("ServerData", "D-MinimapSpotting"))
        toSend.set("PacketData", "UGID", server.serverData.get("ServerData", "UGID"))
        toSend.set("PacketData", "D-ServerDescriptionCount", "0")  # Server Description? What is it? # TODO: Make support for Server Descriptions
        try:
            toSend.set("PacketData", "D-BannerUrl", server.serverData.get("ServerData", "D-BannerUrl"))
        except:
            pass
        toSend.set("PacketData", "D-ThirdPersonVehicleCameras", server.serverData.get("ServerData", "D-ThirdPersonVehicleCameras"))
        toSend.set("PacketData", "D-ThreeDSpotting", server.serverData.get("ServerData", "D-ThreeDSpotting"))

        playersData = []
        for i in range(32):
            if len(str(i)) == 1:
                curr = "0" + str(i)
            else:
                curr = str(i)

            pdat = server.serverData.get("ServerData", "D-pdat" + curr)

            if pdat != "|0|0|0|0":
                playersData.append(pdat)

        Packet(toSend).send(self, "GDET", 0x00000000, 0)

        for player in playersData:
            for playerOnServer in server.connectedPlayers:
                if playerOnServer.personaName == player.split('|')[0]:
                    toSend = Packet().create()
                    toSend.set("PacketData", "NAME", playerOnServer.personaName)
                    toSend.set("PacketData", "TID", str(data.get("PacketData", "TID")))
                    toSend.set("PacketData", "PID", str(playerOnServer.playerID))
                    toSend.set("PacketData", "UID", str(playerOnServer.personaID))
                    toSend.set("PacketData", "LID", lobbyID)
                    toSend.set("PacketData", "GID", gameID)
                    Packet(toSend).send(self, "PDAT", 0x00000000, 0)
    else:
        toSend = Packet().create()
        toSend.set("PacketData", "TID", str(data.get("PacketData", "TID")))
        Packet(toSend).send(self, "GDAT", 0x00000000, 0)


def LLST(self, data):
    """ Lobby List """

    toSend = Packet().create()
    toSend.set("PacketData", "TID", str(data.get("PacketData", "TID")))
    toSend.set("PacketData", "NUM-LOBBIES", "1")  # TODO: Make support for more than one lobby
    Packet(toSend).send(self, "LLST", 0x00000000, 0)

    """ Lobby Data """

    toSend = Packet().create()
    toSend.set("PacketData", "TID", str(data.get("PacketData", "TID")))
    toSend.set("PacketData", "LID", "1")
    toSend.set("PacketData", "PASSING", str(len(Servers)))
    toSend.set("PacketData", "NAME", "bfbc2_01")
    toSend.set("PacketData", "LOCALE", "en_US")
    toSend.set("PacketData", "MAX-GAMES", "1000")
    toSend.set("PacketData", "FAVORITE-GAMES", "0")
    toSend.set("PacketData", "FAVORITE-PLAYERS", "0")
    toSend.set("PacketData", "NUM-GAMES", str(len(Servers)))
    Packet(toSend).send(self, "LDAT", 0x00000000, 0)


def GLST(self, data):
    """ Game List """

    toSend = Packet().create()
    toSend.set("PacketData", "TID", str(data.get("PacketData", "TID")))
    toSend.set("PacketData", "LID", "1")
    toSend.set("PacketData", "LOBBY-NUM-GAMES", str(len(Servers)))
    toSend.set("PacketData", "LOBBY-MAX-GAMES", "1000")
    toSend.set("PacketData", "FAVORITE-GAMES", "0")
    toSend.set("PacketData", "FAVORITE-PLAYERS", "0")
    toSend.set("PacketData", "NUM-GAMES", str(len(Servers) - self.CONNOBJ.filteredServers))

    Packet(toSend).send(self, "GLST", 0x00000000, 0)

    if len(Servers) == 0 or self.CONNOBJ.filteredServers == len(Servers):
        self.CONNOBJ.filteredServers = 0
    else:
        """ Game Data """

        while self.CONNOBJ.filteredServers != len(Servers):
            try:
                server = Servers[self.CONNOBJ.filteredServers]

                toSend = Packet().create()
                toSend.set("PacketData", "TID", str(data.get("PacketData", "TID")))
                toSend.set("PacketData", "LID", "1")  # id of lobby
                toSend.set("PacketData", "GID", str(server.gameID))  # id of game/server
                toSend.set("PacketData", "HN", server.personaName)  # account name of server (host name)
                toSend.set("PacketData", "HU", str(server.userID))  # account id of server (host user)
                toSend.set("PacketData", "N", str(server.serverData.get("ServerData", "NAME")))  # name of server in list

                toSend.set("PacketData", "I", server.ipAddr)
                toSend.set("PacketData", "P", str(server.serverData.get("ServerData", "PORT")))  # Port

                toSend.set("PacketData", "JP", str(server.joiningPlayers))  # Players that are joining the server right now?
                toSend.set("PacketData", "QP", str(server.serverData.get("ServerData", "B-U-QueueLength")))  # Something with the queue...lets just set this equal to B-U-QueueLength
                toSend.set("PacketData", "AP", str(server.activePlayers))  # current number of players on server
                toSend.set("PacketData", "MP", str(server.serverData.get("ServerData", "MAX-PLAYERS")))  # Maximum players on server
                toSend.set("PacketData", "PL", "PC")  # Platform - PC / XENON / PS3

                """ Constants """
                toSend.set("PacketData", "F", "0")  # ???
                toSend.set("PacketData", "NF", "0")  # ???
                toSend.set("PacketData", "J", str(server.serverData.get("ServerData", "JOIN")))  # ??? constant value - "O"
                toSend.set("PacketData", "TYPE", str(server.serverData.get("ServerData", "TYPE")))  # what type?? constant value - "G"
                toSend.set("PacketData", "PW", "0")  # ??? - its certainly not something like "hasPassword"

                """ Other server specific values """
                toSend.set("PacketData", "B-U-Softcore", str(server.serverData.get("ServerData", "B-U-Softcore")))  # Game is softcore - what does that mean?
                toSend.set("PacketData", "B-U-Hardcore", str(server.serverData.get("ServerData", "B-U-Hardcore")))  # Game is hardcore
                toSend.set("PacketData", "B-U-HasPassword", str(server.serverData.get("ServerData", "B-U-HasPassword")))  # Game has password
                toSend.set("PacketData", "B-U-Punkbuster", str(server.serverData.get("ServerData", "B-U-Punkbuster")))  # Game has punkbuster?
                toSend.set("PacketData", "B-U-EA", str(server.serverData.get("ServerData", "B-U-EA")))  # is server EA Orginal?
                toSend.set("PacketData", "B-version", str(server.serverData.get("ServerData", "B-version")))  # Version of the server (exact version) - TRY TO CONNECT TO ACTUAL VERSION OF SERVER
                toSend.set("PacketData", "V", str(server.clientVersion))  # "clientVersion" of server (shows up in server log on startup)
                toSend.set("PacketData", "B-U-level", str(server.serverData.get("ServerData", "B-U-level")))  # current map of server
                toSend.set("PacketData", "B-U-gamemode", str(server.serverData.get("ServerData", "B-U-gamemode")))  # Gameplay Mode (Conquest, Rush, SQDM,  etc)
                toSend.set("PacketData", "B-U-sguid", str(server.serverData.get("ServerData", "B-U-sguid")))  # Game PB Server GUID?
                toSend.set("PacketData", "B-U-Time", str(server.serverData.get("ServerData", "B-U-Time")))  # uptime of server?
                toSend.set("PacketData", "B-U-hash", str(server.serverData.get("ServerData", "B-U-hash")))  # Game hash?
                toSend.set("PacketData", "B-U-region", str(server.serverData.get("ServerData", "B-U-region")))  # Game region
                toSend.set("PacketData", "B-U-public", str(server.serverData.get("ServerData", "B-U-public")))  # Game is public
                toSend.set("PacketData", "B-U-elo", str(server.serverData.get("ServerData", "B-U-elo")))  # value that determines how good the players on the server are?

                toSend.set("PacketData", "B-numObservers", str(server.serverData.get("ServerData", "B-numObservers")))  # Observers = spectators? or admins?
                toSend.set("PacketData", "B-maxObservers", str(server.serverData.get("ServerData", "B-maxObservers")))  # Game max observers

                toSend.set("PacketData", "B-U-Provider", str(server.serverData.get("ServerData", "B-U-Provider")))  # provider id, figured out by server
                toSend.set("PacketData", "B-U-gameMod", str(server.serverData.get("ServerData", "B-U-gameMod")))  # maybe different value for vietnam here?
                toSend.set("PacketData", "B-U-QueueLength", str(server.serverData.get("ServerData", "B-U-QueueLength")))  # players in queue or maximum queue length? (sometimes smaller than QP (-1?))

                if server.serverData.get("ServerData", "B-U-Punkbuster") == 1:
                    toSend.set("PacketData", server.serverData.get("ServerData", "B-U-PunkbusterVersion"))
            except AttributeError:
                pass

            Packet(toSend).send(self, "GDAT", 0x00000000, 0)
            self.CONNOBJ.filteredServers += 1


def EGAM(self, data):
    self.logger.notification("[" + self.ip + ":" + str(self.port) + "] wants to join server", 1)

    lid = data.get("PacketData", "LID")
    gid = data.get("PacketData", "GID")

    toSendEGAM = Packet().create()
    toSendEGAM.set("PacketData", "TID", str(data.get("PacketData", "TID")))
    toSendEGAM.set("PacketData", "LID", str(lid))
    toSendEGAM.set("PacketData", "GID", str(gid))

    server = None
    for tempServer in Servers:
        if tempServer.serverData.get("ServerData", "GID") == str(gid):
            tempServer.newPlayerID += 1
            server = tempServer
            break

    if server is not None:
        """ This packet gets sent to the SERVER the client connects to, it contains information about the client """

        self.CONNOBJ.playerID = server.newPlayerID
        server.connectedPlayers.append(self.CONNOBJ)

        ticket = GenerateRandomString(10)

        toSend = Packet().create()
        toSend.set("PacketData", "R-INT-PORT", str(data.get("PacketData", "R-INT-PORT")))
        toSend.set("PacketData", "R-INT-IP", str(data.get("PacketData", "R-INT-IP")))  # internal ip where the CLIENT is hosted
        toSend.set("PacketData", "PORT", str(data.get("PacketData", "PORT")))
        toSend.set("PacketData", "NAME", self.CONNOBJ.personaName)
        toSend.set("PacketData", "PTYPE", str(data.get("PacketData", "PTYPE")))
        toSend.set("PacketData", "TICKET", ticket)
        toSend.set("PacketData", "PID", str(self.CONNOBJ.playerID))
        toSend.set("PacketData", "UID", str(self.CONNOBJ.personaID))
        toSend.set("PacketData", "IP", self.CONNOBJ.ipAddr)

        toSend.set("PacketData", "LID", str(lid))
        toSend.set("PacketData", "GID", str(gid))

        Packet(toSend).send(server.theaterInt, "EGRQ", 0x00000000, 0)
        Packet(toSendEGAM).send(self, "EGAM", 0x00000000, 0)

        toSend = Packet().create()
        toSend.set("PacketData", "PL", "pc")
        toSend.set("PacketData", "TICKET", ticket)
        toSend.set("PacketData", "PID", str(self.CONNOBJ.playerID))

        toSend.set("PacketData", "I", server.ipAddr)
        toSend.set("PacketData", "P", str(server.serverData.get("ServerData", "PORT")))  # Port

        toSend.set("PacketData", "HUID", str(server.personaID))
        toSend.set("PacketData", "INT-PORT", str(server.serverData.get("ServerData", "INT-PORT")))  # Port
        toSend.set("PacketData", "EKEY", "AIBSgPFqRDg0TfdXW1zUGa4%3d")  # this must be the same key as the one we have on the server? keep it constant in both connections for now (we could integrate it in the database...)
        toSend.set("PacketData", "INT-IP", server.serverData.get("ServerData", "INT-IP"))  # internal ip where the SERVER is hosted
        toSend.set("PacketData", "UGID", server.serverData.get("ServerData", "UGID"))
        toSend.set("PacketData", "LID", str(lid))
        toSend.set("PacketData", "GID", str(gid))

        Packet(toSend).send(self, "EGEG", 0x00000000, 0)


def ECNL(self, data):
    lobbyID = str(data.get("PacketData", "LID"))
    gameID = str(data.get("PacketData", "GID"))

    toSend = Packet().create()
    toSend.set("PacketData", "TID", str(data.get("PacketData", "TID")))
    toSend.set("PacketData", "LID", lobbyID)
    toSend.set("PacketData", "GID", gameID)
    Packet(toSend).send(self, "ECNL", 0x00000000, 0)
