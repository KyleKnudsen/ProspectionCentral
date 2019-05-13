# Global utility function file

import json
from definitions import ROOT_DIR


def get_response_message(feature, category, result, entry):
    try:
        with open(ROOT_DIR + "/webapp/response_messages.json") as response_messages:
            data = json.load(response_messages)
            return data[feature][category][result][entry]
    except:
        print("get_response_message failed execution")
