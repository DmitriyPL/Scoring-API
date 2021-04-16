#!/usr/bin/env python
# -*- coding: utf-8 -*-

import datetime
import logging
import hashlib
import json
import uuid
import re

from optparse import OptionParser
from http.server import HTTPServer, BaseHTTPRequestHandler

import scoring
from store import RedisConnection


SALT = "Otus"
ADMIN_LOGIN = "admin"
ADMIN_SALT = "42"
OK = 200
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404
INVALID_REQUEST = 422
INTERNAL_ERROR = 500
ERRORS = {
    BAD_REQUEST: "Bad Request",
    FORBIDDEN: "Forbidden",
    NOT_FOUND: "Not Found",
    INVALID_REQUEST: "Invalid Request",
    INTERNAL_ERROR: "Internal Server Error",
}
UNKNOWN = 0
MALE = 1
FEMALE = 2
GENDERS = {
    UNKNOWN: "unknown",
    MALE: "male",
    FEMALE: "female",
}
EMAIL_REGEX = re.compile(r'[\d|\w].*@.*.\w*')
PHONE_REGEX = re.compile(r'^7\d{10}$')
DATA_REGEX = re.compile(r'^(\d{2}).(\d{2}).\d{4}$')


class Field(object):
    def __init__(self, nullable=False, required=False):
        self.nullable = nullable
        self.required = required

    def __set_name__(self, owner, name):
        self.name = name

    def parse_validate(self, value):
        if not self.nullable and not value:
            raise ValueError("can't be empty")
        return value


class CharField(Field):
    def parse_validate(self, value):
        value = super(CharField, self).parse_validate(value)
        if isinstance(value, str):
            return value
        raise ValueError("isn't <str>")

    def just_return_value(self, value):
        if (not self.required and not value) or (self.nullable and not value):
            return True
        return False


class ArgumentsField(Field):
    def parse_validate(self, value):
        value = super(ArgumentsField, self).parse_validate(value)
        if isinstance(value, dict):
            return value
        raise ValueError("isn't <dict>")


class EmailField(CharField):
    def parse_validate(self, value):
        value = super(EmailField, self).parse_validate(value)
        if self.just_return_value(value):
            return value
        elif EMAIL_REGEX.match(value):
            return value
        raise ValueError("isn't <e-mail : ...@...>")

    def just_return_value(self, value):
        return super(EmailField, self).just_return_value(value)


class PhoneField(Field):
    def parse_validate(self, value):
        value = super(PhoneField, self).parse_validate(value)
        if not isinstance(value, (int, str)):
            raise ValueError("wrong format")
        elif self.nullable and value != 0 and not value:
            return value
        elif len(str(value)) != 11:
            raise ValueError("should be 11 symbols in phone")
        elif PHONE_REGEX.match(str(value)):
            return value
        raise ValueError("isn't <phone : (7)1234252678>")


class DateField(CharField):
    def parse_validate(self, value):
        value = super(DateField, self).parse_validate(value)
        if self.just_return_value(value):
            return value
        res = DATA_REGEX.match(value)
        err = ""
        if not res:
            err = "isn't <data : DD.MM.YYYY>"
        elif int(res.group(1)) < 1 or int(res.group(2)) < 1:
            err = "min value is '1'"
        elif int(res.group(1)) > 31:
            err = "We have only 31 days in month (max)"
        elif int(res.group(2)) > 12:
            err = "We have only 12 month in year (max)"
        if err:
            raise ValueError(err)
        return value

    def just_return_value(self, value):
        return super(DateField, self).just_return_value(value)


class BirthDayField(DateField):
    def parse_validate(self, value):
        value = super(BirthDayField, self).parse_validate(value)
        if self.just_return_value(value):
            return value

        res = DATA_REGEX.match(value)
        date = datetime.datetime.strptime(res.group(), '%d.%m.%Y')
        date_now = datetime.datetime.now()
        if round((date_now - date).days / 365, 1) > 70:
            raise ValueError("More than 70 years have passed")
        return value

    def just_return_value(self, value):
        return super(BirthDayField, self).just_return_value(value)


class GenderField(Field):
    def parse_validate(self, value):
        if not self.nullable and value != 0 and not value:
            raise ValueError("can't be empty")
        elif self.nullable and not value:
            return value

        err = ""
        if not isinstance(value, int):
            err = "gender is not <int>"
        elif not (0 <= value <= 2):
            err = "should be <0 - unknown, 1 - male, 2 - female>"
        if err:
            raise ValueError(err)
        return value


class ClientIDsField(Field):
    def parse_validate(self, value):
        value = super(ClientIDsField, self).parse_validate(value)

        err = ""
        if not isinstance(value, list):
            err = "isn't <list>"
        elif not all(map(lambda i: isinstance(i, int), value)):
            err = "only <int> expected"
        if err:
            raise ValueError(err)
        return value


class RequestHandler(object):
    def validate_handle(self, request, arguments, ctx, store):
        if not arguments.is_valid():
            return arguments.errfmt(), INVALID_REQUEST
        return self.handle(request, arguments, ctx, store)

    def handle(self, request, arguments, ctx):
        return {}, OK


class RequestMeta(type):
    """
        Записывает атрибуты являющиеся инстансами класса Field в field_list
    """
    def __new__(mcs, name, bases, attrs):
        field_list = []
        for v in attrs.values():
            if isinstance(v, Field):
                field_list.append(v)

        cls = super(RequestMeta, mcs).__new__(mcs, name, bases, attrs)
        cls.fields = field_list
        return cls


class Request(metaclass=RequestMeta):

    def __init__(self, request):
        self.errors = []
        self.request = request
        self.is_cleaned = False

    def clean(self):
        """
            1. Проверяем что имеем дело со словарем
            2. Обходим поля и проверяем налачие обязательных полей в ключах тела запроса
            3. Валидируем и устанавливаем значения
            4. Пишем ошибки если есть
        """
        if not isinstance(self.request, dict):
            self.errors.append(ERRORS[INVALID_REQUEST])
            return False
        for f in self.fields:
            f_name = f.name
            f_value = self.request.get(f_name)
            if f.required and f_name not in self.request.keys():
                self.errors.append("'{}' is not defined".format(f_name))
            elif not f.required and f_value is None:
                setattr(self, f_name, self.get_value_for_optional_field(f))
                continue
            else:
                try:
                    setattr(self, f_name, f.parse_validate(f_value))
                except ValueError as e:
                    self.errors.append("'{}' - {}".format(f_name, e))

    def is_valid(self):
        """
            Если ошибок не обнаружено, то все ОК
        """
        if not self.is_cleaned:
            self.clean()
        return not self.errors

    def errfmt(self):
        return ", ".join(self.errors)

    def get_value_for_optional_field(self, field):
        if isinstance(field, ClientIDsField):
            value = []
        elif isinstance(field, ArgumentsField):
            value = {}
        else:
            value = ""
        return value


class ClientsInterestsRequest(Request):
    """
        Определяет структуру запроса по методу "clients_interests"
    """
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)

    def is_valid(self):
        """
            Определяет валидность запроса.
            Используется родительская имплементация в классе Request
        """
        default_valid = super(ClientsInterestsRequest, self).is_valid()
        if not default_valid:
            return False
        return True


class ClientsInterestsHandler(RequestHandler):
    """
        Обработчик для метода "clients_interests"
    """
    request_type = ClientsInterestsRequest

    def handle(self, request, arguments, ctx, store):
        ctx["nclients"] = len(arguments.client_ids)
        return {cid: scoring.get_interests(store, cid) for cid in arguments.client_ids}, OK


class OnlineScoreRequest(Request):
    """
        Определяет структуру запроса по методу "online_score"
    """
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=False)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

    def is_valid(self):
        """
            Определяет валидность запроса.
            Используется родительская имплементация в классе Request
        """
        default_valid = super(OnlineScoreRequest, self).is_valid()
        if default_valid and (
                    (self.phone and self.email) or
                    (self.first_name and self.last_name) or
                    (self.gender in [0, 1, 2] and self.birthday)
                ):
            return True
        self.errors.append(ERRORS[INVALID_REQUEST])
        return False


def add_has_in_ctx(arguments, ctx):
    """Пишем контекст для OnlineScoreRequest"""
    has = []
    for atr, val in arguments.request.items():
        if val or (atr == 'gender' and val == 0):
            has.append(atr)
    ctx["has"] = has


class OnlineScoreHandler(RequestHandler):
    """
        Обработчик для метода "online_score"
    """
    request_type = OnlineScoreRequest

    def handle(self, request, arguments, ctx, store):
        """
            1. Валидируем пары аргументов
            2. Пишем контекст
            3. Возвращаем результат
        """
        add_has_in_ctx(arguments, ctx)

        if request.is_admin:
            return {"score": 42}, OK

        scoring_arg = {
            'phone': arguments.phone,
            'email': arguments.email,
            'birthday': arguments.birthday,
            'gender': arguments.gender,
            'first_name': arguments.first_name,
            'last_name': arguments.last_name,
        }

        score = scoring.get_score(store, **scoring_arg)
        return {"score": score}, OK


class MethodRequest(Request):
    """
        Определяет структуру запроса
    """
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN


def check_auth(request):
    """ Проверяем возможна ли auth """

    if request.is_admin:
        digest = hashlib.sha512((datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT).encode()).hexdigest()
    else:
        digest = hashlib.sha512((request.account + request.login + SALT).encode()).hexdigest()
    if digest == request.token:
        return True
    return False


def method_handler(request, ctx, store):
    """
        1. Создаем инстанс запроса
        2. Валидируем его
        3. Проверяем auth
        4. Получаем обработчик запроса в зависимости от указанного метода
        5. Получаем рез из обработчика
    """
    methods_map = {
        "online_score": OnlineScoreHandler,
        "clients_interests": ClientsInterestsHandler,
    }
    method_request = MethodRequest(request["body"])
    if not method_request.is_valid():
        return method_request.errfmt(), INVALID_REQUEST
    if not check_auth(method_request):
        return None, FORBIDDEN
    handler_cls = methods_map.get(method_request.method)
    if not handler_cls:
        return "'method' not found", NOT_FOUND
    response, code = handler_cls().validate_handle(method_request,
                                                   handler_cls.request_type(method_request.arguments),
                                                   ctx, store)
    return response, code


class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {
        "method": method_handler
    }
    store = RedisConnection()

    def get_request_id(self, headers):
        return headers.get('HTTP_X_REQUEST_ID', uuid.uuid4().hex)

    def do_POST(self):
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}
        request = None
        try:
            data_string = self.rfile.read(int(self.headers['Content-Length']))
            request = json.loads(data_string)
        except:
            code = BAD_REQUEST

        if request:
            path = self.path.strip("/")
            logging.info("%s: %s %s" % (self.path, data_string, context["request_id"]))
            if path in self.router:
                try:
                    response, code = self.router[path]({"body": request, "headers": self.headers}, context, self.store)
                except Exception as e:
                    logging.exception("Unexpected error: %s" % e)
                    code = INTERNAL_ERROR
            else:
                code = NOT_FOUND

        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if code not in ERRORS:
            r = {"response": response, "code": code}
        else:
            # @TODO: return errors as array
            r = {"error": response or ERRORS.get(code, "Unknown Error"), "code": code}
        context.update(r)
        logging.info(context)
        self.wfile.write(json.dumps(r).encode())
        return


if __name__ == "__main__":
    op = OptionParser()
    op.add_option("-p", "--port", action="store", type=int, default=8080)
    op.add_option("-l", "--log", action="store", default=None)
    (opts, args) = op.parse_args()
    logging.basicConfig(filename=opts.log, level=logging.INFO,
                        format='[%(asctime)s] %(levelname).1s %(message)s', datefmt='%Y.%m.%d %H:%M:%S')
    server = HTTPServer(("localhost", opts.port), MainHTTPHandler)
    logging.info("Starting server at %s" % opts.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
