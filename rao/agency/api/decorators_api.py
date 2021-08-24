from django.core import signing
from rest_framework import status
from rest_framework.exceptions import PermissionDenied, APIException
from rest_framework.permissions import BasePermission, SAFE_METHODS

from agency.utils.utils_db import get_operator_by_username


class NotAcceptable(APIException):
    status_code = status.HTTP_406_NOT_ACCEPTABLE
    default_detail = "Token non valido."


class Unauthorized(APIException):
    status_code = status.HTTP_401_UNAUTHORIZED
    default_detail = "Non autorizzato."


class AdminToken(BasePermission):
    def has_permission(self, request, view):
        try:
            token = request.META.get('HTTP_AUTHORIZATION', None)
            params = signing.loads(token, max_age=3600)
        except Exception as e:
            raise NotAcceptable("Sessione scaduta. Effettuare nuovamente l\'accesso")
        if 'is_admin' not in params or 'username' not in params:
            raise NotAcceptable("Token non valido.")
        if not params['is_admin']:
            raise Unauthorized("Gli operatori non possono visualizzare i log.")

        operator = get_operator_by_username(params['username'].upper())

        if not operator.status:
            raise Unauthorized("L'account è disattivato. Apri un ticket per essere riattivato.")
        request.session['username'] = params['username'].upper()
        return True


class OperatorToken(BasePermission):
    def has_permission(self, request, view):
        try:
            token = request.META.get('HTTP_AUTHORIZATION', None)
            params = signing.loads(token, max_age=3600)
        except Exception as e:
            raise NotAcceptable("Sessione scaduta. Effettuare nuovamente l\'accesso")
        if 'is_admin' not in params or 'username' not in params:
            raise NotAcceptable("Token non valido.")

        if params['is_admin']:
            raise Unauthorized("L'amministratore non può generare richieste di identificazione.")

        operator = get_operator_by_username(params['username'])

        if not operator.status or not operator.signStatus:
            raise Unauthorized("L'account è disattivato. Contattare il Security Officer.")
        request.session['username'] = params['username'].upper()
        return True


class ReadOnly(BasePermission):
    def has_permission(self, request, view):
        return request.method in SAFE_METHODS
