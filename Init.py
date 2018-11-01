#! python2.7

import os

from Config import readFromConfig
from Database import Database
from Framework.ErrorCodes import ERROR_FAILED_TO_LOAD_MODULES, ERROR_FAILED_TO_MAKE_SSL_CONTEXT, \
    ERROR_FAILED_TO_INITIALIZE_DATABASE, ERROR_FAILED_TO_BIND_PORT, ERROR_IP_IS_DEFAULT
from Framework.ServerTypes import CLIENT, SERVER
from Network import Plasma, Theater, Http
from Logger import Log, start_log

try:
    from twisted.internet import ssl, reactor
    from twisted.internet.protocol import Factory, Protocol
    from twisted.web.server import Site
    from OpenSSL import SSL
except ImportError as importErr:
    Log("Init").error("Fatal Error!\n"
                      "Cannot import Twisted modules!\n"
                      "Please install all required dependencies using\n"
                      "`pip install -r requirements.txt`\n\n"
                      "Additional error info:\n" + str(importErr), 0)
    os._exit(ERROR_FAILED_TO_LOAD_MODULES)


class ServerFactory(Factory):
    def __init__(self, serverType):
        self.serverType = serverType

        if serverType == SERVER:
            self.nextGameID = 1


def MainApp():
    Log("Init").notification("Initializing Battlefield: Bad Company 2 Master Server Emulator...", 0)

    ssl_key = readFromConfig("SSL", "priv_key_path")
    ssl_cert = readFromConfig("SSL", "cert_file_path")
    plasma_client_port = readFromConfig("emulator", "plasma_client_port")
    plasma_server_port = readFromConfig("emulator", "plasma_server_port")
    theater_client_port = readFromConfig("emulator", "theater_client_port")
    theater_server_port = readFromConfig("emulator", "theater_server_port")
    enable_http = readFromConfig("emulator", "enable_http")
    emulator_ip = readFromConfig("emulator", "emulator_ip")

    if emulator_ip == "REPLACE_ME":
        Log("Config").error("'emulator_ip' still has its default value, its required to replace \"REPLACE_ME\""
                            " with the network IP of the PC where you want to host this emulator for incoming"
                            " connections to be able to connect properly!")
        os._exit(ERROR_IP_IS_DEFAULT)

    try:
        Database(True)
    except Exception as DatabaseError:
        Log("Database").error("Fatal Error! Cannot initialize database!\n\n"
                              "Additional error info:\n" + str(DatabaseError), 0)
        os._exit(ERROR_FAILED_TO_INITIALIZE_DATABASE)

    try:
        SSLContext = ssl.DefaultOpenSSLContextFactory(ssl_key, ssl_cert)
    except Exception as SSLErr:
        Log("Init").error("Fatal Error!\n"
                          "Failed to create SSL Context!\n"
                          "Make sure that you installed all required modules using\n"
                          "`pip install -r requirements.txt`\n"
                          "Also check if you specified correct SSL Cert and/or key in "
                          "`config.ini`\n "
                          "Additional error info:\n" + str(SSLErr), 0)
        os._exit(ERROR_FAILED_TO_MAKE_SSL_CONTEXT)

    try:
        factory = ServerFactory(CLIENT)
        factory.protocol = Plasma.HANDLER
        reactor.listenSSL(plasma_client_port, factory, SSLContext)
        Log("PlasmaClient").notification("Created TCP Socket (now listening on port " + str(plasma_client_port) + ")",
                                         1)
    except Exception as BindError:
        Log("Init").error("Fatal Error! Cannot bind socket to port: " + str(plasma_client_port) +
                          "\nMake sure that this port aren't used by another program!\n\n"
                          "Additional error info:\n" + str(BindError), 0)
        os._exit(ERROR_FAILED_TO_BIND_PORT)

    try:
        factory = ServerFactory(SERVER)
        factory.protocol = Plasma.HANDLER
        reactor.listenSSL(plasma_server_port, factory, SSLContext)
        Log("PlasmaServer").notification("Created TCP Socket (now listening on port " + str(plasma_server_port) + ")",
                                         1)
    except Exception as BindError:
        Log("Init").error("Fatal Error! Cannot bind socket to port: " + str(plasma_server_port) +
                          "\nMake sure that this port aren't used by another program!\n\n"
                          "Additional error info:\n" + str(BindError), 0)
        os._exit(ERROR_FAILED_TO_BIND_PORT)

    try:
        factoryTCP = ServerFactory(CLIENT)
        factoryTCP.protocol = Theater.TCPHandler
        reactor.listenTCP(theater_client_port, factoryTCP)
        Log("TheaterClient").notification("Created TCP Socket (now listening on port " + str(theater_client_port) + ")",
                                          1)
        reactor.listenUDP(theater_client_port, Theater.UDPHandler())
        Log("TheaterClient").notification("Created UDP Socket (now listening on port " + str(theater_client_port) + ")",
                                          1)
    except Exception as BindError:
        Log("Init").error("Fatal Error! Cannot bind socket to port: " + str(theater_client_port) +
                          "\nMake sure that this port aren't used by another program!\n\n"
                          "Additional error info:\n" + str(BindError), 0)
        os._exit(ERROR_FAILED_TO_BIND_PORT)

    try:
        factoryTCP = ServerFactory(SERVER)
        factoryTCP.protocol = Theater.TCPHandler
        reactor.listenTCP(theater_server_port, factoryTCP)
        Log("TheaterServer").notification("Created TCP Socket (now listening on port " + str(theater_server_port) + ")",
                                          1)
        reactor.listenUDP(theater_server_port, Theater.UDPHandler())
        Log("TheaterServer").notification("Created UDP Socket (now listening on port " + str(theater_server_port) + ")",
                                          1)
    except Exception as BindError:
        Log("Init").error("Fatal Error! Cannot bind socket to port: " + str(theater_server_port) +
                          "\nMake sure that this port aren't used by another program!\n\n"
                          "Additional error info:\n" + str(BindError), 0)
        os._exit(ERROR_FAILED_TO_BIND_PORT)

    if enable_http:
        try:
            site = Site(Http.Handler())
            reactor.listenTCP(80, site)
            Log("WebServer").notification("Created TCP Socket (now listening on port 80)", 1)
        except Exception as BindError:
            Log("Init").error("Fatal Error! Cannot bind socket to port: 80"
                              "\nMake sure that this port aren't used by another program!\n\n"
                              "Additional error info:\n" + str(BindError), 0)
            os._exit(ERROR_FAILED_TO_BIND_PORT)

    Log("Init").notification("Finished initialization! Ready for receiving incoming connections...", 0)

    reactor.run()


if __name__ == '__main__':
    start_log()
    MainApp()
