import datetime
import logging

from django.core import signing
from django.db import transaction
from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework.views import APIView

from agency.api.decorators_api import AdminToken, ReadOnly, OperatorToken
from agency.api.utils_rao_api import ud_format
from agency.classes.choices import StatusCode
from agency.forms import LoginForm, NewIdentityApiForm
from agency.utils.utils_mail import send_email
from agency.utils.utils import check_operator, is_admin, from_utc_to_local, render_to_pdf, set_client_ip
from agency.utils.utils_db import create_identity_request, get_operator_by_username, \
    create_identity, update_sign_field_operator, get_log_idr_by_date, get_attributes_RAO
from agency.utils.utils_token import signed_token
from rao import settings
from rao.settings import BASE_URL

LOG = logging.getLogger(__name__)


class AuthViewSet(viewsets.ViewSet):

    def post(self, request):
        """
        Restituisce un token di autenticazione
        :param request: request
        :return: token di sessione
        """
        try:
            LOG.info("API /auth", extra=set_client_ip(request))
            username = request.POST.get('usernameField', None).upper()
            password = request.POST.get('passwordField', None)
            if not username or not password:
                LOG.error("Status {} : Parametri assenti".format(status.HTTP_403_FORBIDDEN))
                return Response("Parametri assenti", status=status.HTTP_403_FORBIDDEN)

            form = LoginForm(request.POST)
            message = "Il formato dei parametri non è corretto"
            if form.is_valid():
                result = check_operator(username, password, request)
                if result == StatusCode.OK.value:
                    params = {
                        'username': username,
                        'is_admin': is_admin(username)
                    }
                    t = signing.dumps(params)
                    message = t
                if result == StatusCode.EXPIRED_TOKEN.value:
                    message = "Password scaduta. Accedi utilizzando l'interfaccia WEB per aggiornarla."
                if result == StatusCode.SIGN_NOT_AVAILABLE.value:
                    message = "Bisogna completare il processo di attivazione"
                if result == StatusCode.UNAUTHORIZED.value:
                    message = "Credenziali bloccate. Contatta il Security Officer."
                if result == StatusCode.ERROR.value:
                    message = "Credenziali errate."
                    result = status.HTTP_401_UNAUTHORIZED
                if result != StatusCode.OK.value:
                    LOG.error("Status {} : {}".format(result if result != StatusCode.EXPIRED_TOKEN.value else status.HTTP_406_NOT_ACCEPTABLE, message))
                return Response(message,
                                status=result if result != StatusCode.EXPIRED_TOKEN.value else status.HTTP_406_NOT_ACCEPTABLE)
            else:
                return Response(message, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            LOG.error("Exception: {}".format(str(e)))
            return Response(status=status.HTTP_406_NOT_ACCEPTABLE)


class TokenViewSet(APIView):
    permission_classes = [OperatorToken]

    def post(self, request):
        """
        Restituisce un token di autenticazione
        :param request: request
        :return: PDF con prima parte passphrase
        """
        try:
            LOG.info("API /token", extra=set_client_ip(request))

            username_operator = request.session['username'].upper()
            form = NewIdentityApiForm(request.POST, username=username_operator)

            if form.is_valid():
                LOG.info("operator: {}, {} - Step1 identificazione OK - Dati inseriti correttamente".format(
                    request.session['username'], request.POST['fiscalNumber']), extra=set_client_ip())
                operator = get_operator_by_username(username_operator)
                ud = create_identity(request, operator.id)
                request.session['username'] = username_operator

                data = {k: v[0] for k, v in dict(request.POST).items()}

                try:
                    with transaction.atomic():
                        id_request = create_identity_request(request, ud)
                        dict_token = signed_token(ud_format(ud), username_operator, get_attributes_RAO(), api_data=data)

                        if not id_request or dict_token['statusCode'] is not StatusCode.OK.value:
                            raise Exception("Step2 identificazione KO - Token non creato")

                        timestamp = from_utc_to_local(id_request.timestamp_identification)

                        mail_elements = {
                            'base_url': BASE_URL,
                            'rao_name': get_attributes_RAO().name,
                            'name_user': request.POST['name'],
                            'surname_user': request.POST['familyName'],
                            'date': timestamp.strftime('%d/%m/%Y'),
                            'time': timestamp.strftime('%H:%M')
                        }

                        email_status_code = send_email([request.POST['email']],
                                                       "SPID - Identificazione presso Sportello Pubblico",
                                                       settings.TEMPLATE_URL_MAIL + 'mail_token.html',
                                                       {'passphrase2': dict_token['passphrase'][6:12],
                                                        'mail_elements': mail_elements},
                                                       [dict_token['token_sigillato']],
                                                       str(id_request.uuid_identity) + "_tuo_pacchetto.txt")

                        if email_status_code != StatusCode.OK.value:
                            raise Exception("Step2 identificazione - Invio mail non riuscita")
                except Exception as e:
                    LOG.warning("operator: {}, {} - {}".format(
                        username_operator, request.POST['fiscalNumber'].upper(), str(e)), extra=set_client_ip())
                    if dict_token['statusCode'] == StatusCode.OK.value:
                        return Response("Errore durante l'invio della mail", status=status.HTTP_406_NOT_ACCEPTABLE)

                    if dict_token['statusCode'] == StatusCode.UNAUTHORIZED.value:
                        return Response("Il pin inserito non è corretto.", status=status.HTTP_401_UNAUTHORIZED)
                    elif dict_token['statusCode'] == StatusCode.SIGN_NOT_AVAILABLE.value:
                        update_sign_field_operator(username_operator, False)
                        return Response("Pin errato per la 3a volta. Account Bloccato.",
                                        status=status.HTTP_401_UNAUTHORIZED)
                    else:
                        return Response("Errore durante la creazione del token", status=status.HTTP_406_NOT_ACCEPTABLE)

                LOG.info("operator: {}, {} - Step2 identificazione OK - Token creato".format(
                    username_operator, request.POST['fiscalNumber']), extra=set_client_ip())
                return render_to_pdf(
                    settings.TEMPLATE_URL_PDF + 'pdf_template.html',
                    {
                        'pagesize': 'A4',
                        'passphrase': dict_token['passphrase'][0:6],
                        'RAO_name': get_attributes_RAO().name,
                        'operator': operator,
                        'name_user': request.POST['name'],
                        'surname_user': request.POST['familyName'],
                        'pdf_object': 'SPID - Identificazione presso Sportello Pubblico',
                        'token_expiration_date': datetime.datetime.strftime(id_request.timestamp_identification,
                                                                            '%Y-%m-%d %H:%M')
                    })
            else:
                LOG.error("Status {} : Parametri assenti o errati".format(status.HTTP_400_BAD_REQUEST))
                return Response(form.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            LOG.error("Exception: {}".format(str(e)), extra=set_client_ip())
            return Response("Errore nella richiesta", status=status.HTTP_406_NOT_ACCEPTABLE)


class LOGViewSet(APIView):
    permission_classes = [ReadOnly, AdminToken]

    def get(self, request, date=None):
        """

        :param request: request
        :param date: data relativa alle identità
        :return: stringa con i log delle identità relativa alla data richiesta
        """
        LOG.info("API /log/{}".format(date), extra=set_client_ip(request))
        if not date:
            return get_log_idr_by_date(datetime.datetime.today().strftime("%Y-%m-%d"))
        else:
            return get_log_idr_by_date(date)
