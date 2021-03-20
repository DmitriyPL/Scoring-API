#!/usr/bin/env python
# -*- coding: utf-8 -*-

import datetime
import logging
import hashlib
import json
import uuid
import re


from http.server import HTTPServer, BaseHTTPRequestHandler
from optparse import OptionParser


import scoring


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
EMAIL_REGEX = re.compile(r'.*@.*')
# PHONE_REGEX = re.compile(r'^[7|8]\d{10}$')
PHONE_REGEX = re.compile(r'^7\d{10}$')
DATA_REGEX = re.compile(r'^(\d{2}).(\d{2}).\d{4}$')
MSG_ERR = ". Field:"


class Field:
    def __init__(self, **atrs):
        for key, value in atrs.items():
            setattr(self, key, value)

    def __set_name__(self, owner, name):
        self.name = name

    def __get__(self, instance, owner):
        if instance is None:
            return self
        else:
            return instance.__dict__[self.name]

    def __set__(self, instance, value):
        instance.__dict__[self.name] = value

    def validate_able_nullable(self, value):
        if self.nullable and not value:
            return True
        else:
            return False


class CharField(Field):
    def __set__(self, instance, value):
        self.validate_char_field(value)
        super().__set__(instance, value)

    def validate_char_field(self, value):
        if self.validate_able_nullable(value):
            return False
        else:
            is_bad_field = False
            err = ""

            # На None не проверяю, т.к. в json нельзя не передать хоть что то...
            if not isinstance(value, str):
                is_bad_field = True
                err = "{} '{}' is not <str>".format(MSG_ERR, self.name)
            elif not self.nullable and not value:
                is_bad_field = True
                err = "{} '{}' is empty".format(MSG_ERR, self.name)

            if is_bad_field:
                raise ValueError(INVALID_REQUEST, err)

            return True

    def validate_able_nullable(self, value):
        return super().validate_able_nullable(value)


class ArgumentsField(Field):
    def __set__(self, instance, value):
        self.validate_arg_field(value)
        super().__set__(instance, value)

    def validate_arg_field(self, value):
        is_bad_field = False
        err = ""

        if not isinstance(value, dict):
            is_bad_field = True
            err = "{} '{}' is not <dict>".format(MSG_ERR, self.name)
        if self.validate_able_nullable(value):
            pass
        elif not value:
            is_bad_field = True
            err = "{} '{}' is empty".format(MSG_ERR, self.name)

        if is_bad_field:
            raise ValueError(INVALID_REQUEST, err)

        return True

    def validate_able_nullable(self, value):
        return super().validate_able_nullable(value)


class EmailField(CharField):
    def __set__(self, instance, value):
        self.validate_email_field(value)
        super().__set__(instance, value)

    def validate_char_field(self, value):
        return super().validate_char_field(value)

    def validate_email_field(self, value):
        if not self.validate_char_field(value):
            return False
        else:
            if not EMAIL_REGEX.match(value):
                err = "{} '{}' is not <e-mail : ...@...>".format(MSG_ERR, self.name)
                raise ValueError(INVALID_REQUEST, err)

        return True


class PhoneField(Field):
    def __set__(self, instance, value):
        self.validate_phone_field(value)
        super().__set__(instance, value)

    def validate_phone_field(self, value):
        if self.validate_able_nullable(value):
            return False
        else:
            bad_field = False
            err = ""

            if not self.nullable and not value:
                bad_field = True
                err = "{} '{}' is empty".format(MSG_ERR, self.name)
            elif not PHONE_REGEX.match(str(value)):
                bad_field = True
                err = "{} '{}' is not <phone : (7|8)1234252678>".format(MSG_ERR, self.name)

            if bad_field:
                raise ValueError(INVALID_REQUEST, err)

        return True

    def validate_able_nullable(self, value):
        return super().validate_able_nullable(value)


class DateField(CharField):
    def __set__(self, instance, value):
        self.validate_date_field(value)
        super().__set__(instance, value)

    def validate_char_field(self, value):
        return super().validate_char_field(value)

    def validate_date_field(self, value):
        if not self.validate_char_field(value):
            return False
        else:
            bad_field = False
            err = ""

            res = DATA_REGEX.match(value)
            if not res:
                err = "{} '{}' is not <data : DD.MM.YYYY>".format(MSG_ERR, self.name)
                bad_field = True
            elif int(res.group(1)) > 31:
                err = "{} '{}' wrong. We have only 31 days in month (max)".format(MSG_ERR, self.name)
                bad_field = True
            elif int(res.group(2)) > 12:
                err = "{} '{}' wrong. We have only 12 month in year (max)".format(MSG_ERR, self.name)
                bad_field = True

            if bad_field:
                raise ValueError(INVALID_REQUEST, err)
        return True


class BirthDayField(DateField):
    def __set__(self, instance, value):
        self.validate_birthday_field(value)
        super().__set__(instance, value)

    def validate_date_field(self, value):
        return super().validate_date_field(value)

    def validate_birthday_field(self, value):
        if not self.validate_date_field(value):
            return False
        else:
            res = DATA_REGEX.match(value)
            date = datetime.datetime.strptime(res.group(), '%d.%m.%Y')
            date_now = datetime.datetime.now()
            if round((date_now - date).days / 365, 1) > 70:
                err = "{} '{}' wrong. More than 70 years have passed".format(MSG_ERR, self.name)
                raise ValueError(INVALID_REQUEST, err)
        return True


class GenderField(Field):
    def __set__(self, instance, value):
        self.validate_gender_field(value)
        super().__set__(instance, value)

    def validate_gender_field(self, value):
        if self.validate_able_nullable(value):
            return False
        else:
            bad_field = False
            err = ""

            if not isinstance(value, int):
                bad_field = True
                err = "{} '{}' - gender is not <int>".format(MSG_ERR, self.name)
            elif not (0 <= value <= 2):
                bad_field = True
                err = "{} '{}' - wrong gender <0 - unknown, 1 - male, 2 - female>".format(MSG_ERR, self.name)

            if bad_field:
                raise ValueError(INVALID_REQUEST, err)
        return True

    def validate_able_nullable(self, value):
        return super().validate_able_nullable(value)


class ClientIDsField(Field):
    def __set__(self, instance, value):
        self.validate_id_fields(value)
        super().__set__(instance, value)

    def validate_id_fields(self, value):
        if self.validate_able_nullable(value):
            return False
        else:
            bad_field = False
            err = ""

            if not isinstance(value, list):
                bad_field = True
                err = "{} '{}' - is not <list>".format(MSG_ERR, self.name)
            elif not self.nullable and len(value) == 0:
                bad_field = True
                err = "{} '{}' - is empty".format(MSG_ERR, self.name)
            elif not all(map(lambda i: isinstance(i, int), value)):
                bad_field = True
                err = "{} '{}' - only <int> expected".format(MSG_ERR, self.name)

            if bad_field:
                raise ValueError(INVALID_REQUEST, err)
        return True

    def validate_able_nullable(self, value):
        return super().validate_able_nullable(value)


class ClientsInterestsRequest(Field):
    client_ids = ClientIDsField(required=True, nullable=False)
    date = DateField(required=False, nullable=True)


class OnlineScoreRequest(object):
    phone = PhoneField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)


class MethodRequest(object):
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    method = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)

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


def get_instance(cls, arguments):
    """
        1. Перебераем атрибуты класса, проверяем флаг 'required' и наличие их в запросе.
           Тем самым, валидируя запрос по обязательным полям.
        2. Устанавливаем атрибатам класса значения из запроса.
           Тут идет валидация уже по полям
        3. Считаем что атрибуты 'required' и 'nullable' - обязательно существуют!
    """

    _dict = cls.__dict__
    inst = cls()

    for cls_atr, atr_type in _dict.items():
        if hasattr(atr_type, 'required'):
            atr_val = arguments.get(cls_atr)
            if getattr(atr_type, 'required') and cls_atr not in arguments:
                raise ValueError(INVALID_REQUEST, ". Field: '{}' not defined".format(cls_atr))
            else:
                if atr_val is None:
                    continue
            setattr(inst, cls_atr, atr_val)

    return inst


def add_atr_in_ctx(inst, ctx):
    """ Пишем данные в контекст в зависимости от типа запроса"""

    if isinstance(inst, OnlineScoreRequest):
        has = []
        for atr, val in inst.__dict__.items():
            if val or (atr == 'gender' and val == 0):
                has.append(atr)
        ctx["has"] = has
    elif isinstance(inst, ClientsInterestsRequest):
        ctx["nclients"] = len(inst.client_ids)


def get_scoring_param(request):
    """
        1. Формируем праметры для скоринга
        2. В инстансе OnlineScoreRequest не факт что могут оказаться нужные поля
           поэтому приходится проверять по требуемым параметрам скоринга
    """
    res = {'phone': request.__dict__.get('phone'),
           'email': request.__dict__.get('email'),
           'first_name': request.__dict__.get('first_name'),
           'last_name': request.__dict__.get('last_name'),
           'gender': request.__dict__.get('gender'),
           'birthday': request.__dict__.get('birthday')
           }
    return res


def validate_score_request(sc_param):
    """ Валидируем запрос по условию наличия пар заполненых параметров """

    if (sc_param['phone'] and sc_param['email']) or \
            (sc_param['first_name'] and sc_param['last_name']) or \
            (sc_param['gender'] in [0, 1, 2]) and sc_param['birthday']:
        return True
    return False


def online_score_handler(store, arguments, ctx):
    """
        1. Получаем инстанс класса OnlineScoreRequest
        2. Обновляем контекст
        3. Вормируем параметры для скоринга
        4. Возвращаем результат
    """
    r_score = get_instance(OnlineScoreRequest, arguments)
    add_atr_in_ctx(r_score, ctx)
    scoring_param = get_scoring_param(r_score)

    if validate_score_request(scoring_param):
        score = scoring.get_score(store,
                                  scoring_param['phone'],
                                  scoring_param['email'],
                                  birthday=scoring_param['birthday'],
                                  gender=scoring_param['gender'],
                                  first_name=scoring_param['first_name'],
                                  last_name=scoring_param['last_name']
                                  )
        return {"score": score}, OK
    else:
        return ERRORS[INVALID_REQUEST], INVALID_REQUEST


def clients_interests_handler(store, arguments, ctx):
    """
        1. Получаем инстанс класса ClientsInterestsRequest
        2. Обновляем контекст
        3. Получаем результат из scoring.get_interests
    """

    r_interests = get_instance(ClientsInterestsRequest, arguments)

    try:
        client_ids = r_interests.client_ids
    except KeyError:
        raise ValueError(FORBIDDEN, "")

    add_atr_in_ctx(r_interests, ctx)
    response = {}
    for id in client_ids:
        response[id] = scoring.get_interests(store, id)

    return response, OK


def method_handler(request, ctx, store):
    """
        1. Получаем инстанс класса запроса
        2. Получаем переданный метод
        3. Обрабатываем результат согласно метода
    """
    try:
        r_method = get_instance(MethodRequest, request['body'])
        try:
            if not check_auth(r_method):
                raise ValueError(FORBIDDEN, "")
            method = r_method.method
            arguments = r_method.arguments
        except KeyError:
            raise ValueError(FORBIDDEN, "")

        if method == "online_score":
            if r_method.is_admin:
                return {"score": 42}, OK
            return online_score_handler(store, arguments, ctx)
        elif method == "clients_interests":
            return clients_interests_handler(store, arguments, ctx)
        else:
            return ERRORS[NOT_FOUND], NOT_FOUND

    except ValueError as err:
        code = err.args[0]
        response = "{}{}".format(ERRORS[code], err.args[1])
        return response, code


class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {
        "method": method_handler
    }
    store = None

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
                except Exception as err:
                    logging.exception("Unexpected error: %s" % err)
                    code = INTERNAL_ERROR
            else:
                code = NOT_FOUND

        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if code not in ERRORS:
            r = {"response": response, "code": code}
        else:
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
