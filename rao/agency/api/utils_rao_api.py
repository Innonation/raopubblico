import datetime

from rest_framework.utils import json


def ud_format(ud):
    identity = json.dumps(ud.to_json())
    identity = json.loads(json.loads(identity))
    identity['dateOfBirth'] = datetime.datetime.strptime(identity['dateOfBirth'], '%d/%m/%Y')
    identity['idCardIssueDate'] = datetime.datetime.strptime(identity['idCardIssueDate'], '%d/%m/%Y')
    identity['idCardExpirationDate'] = datetime.datetime.strptime(identity['idCardExpirationDate'],
                                                                  '%d/%m/%Y')
    identity['identificationExpirationDate'] = datetime.datetime.strptime(
        identity['identificationExpirationDate'], '%d/%m/%Y')
    return identity
