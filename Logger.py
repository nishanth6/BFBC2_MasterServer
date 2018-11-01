from colorama import init, Fore

from time import gmtime, strftime
from os import remove

from Config import readFromConfig


def start_log():
    global log_filename

    if not readFromConfig("debug", "log_timestamp"):
        log_filename = "server.log"

        try:
            remove(log_filename)
        except:
            pass
    else:
        log_filename = "server_" + str(strftime("%Y_%m_%d__%H_%M_%S", gmtime())) + ".log"


class Log(object):

    notificationColor = "\33[97m"
    warningColor = Fore.YELLOW
    errorColor = Fore.RED

    plasmaClientNotification = Fore.CYAN
    plasmaServerNotification = Fore.BLUE
    theaterClientNotification = Fore.GREEN
    theaterServerNotification = Fore.MAGENTA
    httpNotification = "\33[96m"

    def __init__(self, messageFrom=""):
        init()

        self.messageFrom = messageFrom

        self.logFile = readFromConfig("debug", "create_log")
        self.logTimestamp = readFromConfig("debug", "log_timestamp")
        self.fileLogLevel = int(readFromConfig("debug", "file_log_level"))
        self.consoleLogLevel = int(readFromConfig("debug", "console_log_level"))

        self.useColors = readFromConfig("console", "use_colors")

    def notification(self, message, level=0):
        notificationColors = {
            "PlasmaClient": Log.plasmaClientNotification,
            "PlasmaServer": Log.plasmaServerNotification,
            "TheaterClient": Log.theaterClientNotification,
            "TheaterServer": Log.theaterServerNotification,
            "WebServer": Log.httpNotification
        }

        self.__new_message(message, notificationColors.get(self.messageFrom, Log.notificationColor), level)

    def warning(self, message, level=0):
        self.__new_message(message, Log.warningColor, level)

    def error(self, message, level=0):
        self.__new_message(message, Log.errorColor, level)

    def __new_message(self, message, color, level):
        timestamp = str(strftime("%d.%m.%Y %H:%M:%S", gmtime()))

        if self.logFile:
            if level <= self.fileLogLevel:
                saveToLog = "[" + timestamp + "][" + self.messageFrom + "] " + message + "\n"

                try:
                    with open(log_filename, "a") as logfile:
                        logfile.write(saveToLog)
                except NameError:
                    start_log()

        if level <= self.consoleLogLevel:
            consoleMessage = "[" + timestamp + "]" + "[" + self.messageFrom + "] " + message

            if self.useColors:
                consoleMessage = color + consoleMessage + Fore.RESET

            print(consoleMessage)
