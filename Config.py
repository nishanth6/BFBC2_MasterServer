from colorama import Fore

import os
import commentjson

from Framework.ErrorCodes import ERROR_FAILED_TO_LOAD_CONFIG, ERROR_FAILED_TO_READ_CONFIG

try:
    configFile = commentjson.load(file(os.path.join(os.path.abspath(os.path.dirname(__file__)), 'config.json')))
except:
    print Fore.RED + "Failed to load config.json\nThis program cannot continue" + Fore.RESET
    os._exit(ERROR_FAILED_TO_LOAD_CONFIG)


def readFromConfig(section, parameter):
    try:
        return configFile[section][parameter]
    except:
        print Fore.RED + "Failed to load certain values in the config.json, be sure that EVERY option has a valid value and try it again.\nThis program cannot continue" + Fore.RESET
        os._exit(ERROR_FAILED_TO_READ_CONFIG)
