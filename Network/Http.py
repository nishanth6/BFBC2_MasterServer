from twisted.web.resource import Resource

from Globals import Clients
from Logger import Log

logger = Log("WebServer")


class Handler(Resource):
    isLeaf = True

    def render_GET(self, request):
        uri = request.uri

        logger.notification("Got HTTP GET request: " + uri, 3)

        if uri == "/easo/editorial/BF/2010/BFBC2/config/PC/game.xml":
            with open('Data/game.xml', 'r') as gamexml:
                request.setHeader("Content-Type", "application/xml")
                return gamexml.read()
        elif uri == '/easo/editorial/BF/2010/BFBC2/config/PC/version':
            with open('Data/version.txt', 'r') as version:
                return version.read()
        elif uri.find('/fileupload/locker2.jsp') != -1:
            args = request.args

            for client in Clients:
                if client.personaName == args['pers'][0]:
                    request.setHeader("Content-Type", "application/xml")
                    response = '<?xml version="1.0" encoding="UTF-8"?>\n<LOCKER error="0" game="/eagames/bfbc2" maxBytes="2867200" maxFiles="10" numBytes="0" numFiles="0" ownr="' + str(client.personaID) + '" pers="' + str(client.personaName) + '"/>'
                    return response
        else:
            logger.warning("Unknown GET: " + request.uri, 2)
