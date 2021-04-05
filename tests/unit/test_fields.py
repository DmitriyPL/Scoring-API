import functools
import unittest


from api import CharField, ArgumentsField, EmailField, PhoneField, DateField, BirthDayField, GenderField, ClientIDsField


def cases(cases):
    def decorator(f):
        @functools.wraps(f)
        def wrapper(*args):
            for c in cases:
                new_args = args + (c if isinstance(c, tuple) else (c,))
                f(*new_args)
        return wrapper
    return decorator


class TestSuite(unittest.TestCase):

    def validate_value_for_cls_instance(self, instance, value):
        try:
            instance.parse_validate(value)
            return True
        except ValueError:
            return False

    @cases([
        {"required": False, "nullable": True, "value": 0},
        {"required": False, "nullable": False, "value": ""}
    ])
    def test_charfield_bad_value(self, test_case):
        instance = CharField(required=test_case['required'], nullable=test_case['nullable'])
        self.assertEqual(self.validate_value_for_cls_instance(instance, test_case['value']), False,
                         msg='{}'.format(test_case))

    @cases([
        {"required": False, "nullable": True, "value": ""},
        {"required": False, "nullable": False, "value": "1"},
        {"required": False, "nullable": False, "value": "dfgdfg"}
    ])
    def test_char_field_good_value(self, test_case):
        instance = CharField(required=test_case['required'], nullable=test_case['nullable'])
        self.assertEqual(self.validate_value_for_cls_instance(instance, test_case['value']), True,
                         msg='{}'.format(test_case))

    @cases([
        {"required": False, "nullable": True, "value": 0},
        {"required": False, "nullable": True, "value": []},
        {"required": False, "nullable": True, "value": ""},
        {"required": False, "nullable": False, "value": {}}
    ])
    def test_arguments_field_bad_value(self, test_case):
        instance = ArgumentsField(required=test_case['required'], nullable=test_case['nullable'])
        self.assertEqual(self.validate_value_for_cls_instance(instance, test_case['value']), False,
                         msg='{}'.format(test_case))

    @cases([
        {"required": False, "nullable": False, "value": {"name": "Ivan"}},
        {"required": False, "nullable": True, "value": {}}
    ])
    def test_arguments_field_good_value(self, test_case):
        instance = ArgumentsField(required=test_case['required'], nullable=test_case['nullable'])
        self.assertEqual(self.validate_value_for_cls_instance(instance, test_case['value']), True,
                         msg='{}'.format(test_case))

    @cases([
        {"required": False, "nullable": True, "value": 0},
        {"required": False, "nullable": False, "value": "1"},
        {"required": False, "nullable": True, "value": "plhome.yandex.ru"},
        {"required": False, "nullable": True, "value": "plhome.yandex.ru@"},
        {"required": False, "nullable": True, "value": "@plhome.yandex.ru"}
    ])
    def test_email_field_bad_value(self, test_case):
        instance = EmailField(required=test_case['required'], nullable=test_case['nullable'])
        self.assertEqual(self.validate_value_for_cls_instance(instance, test_case['value']), False,
                         msg='{}'.format(test_case))

    @cases([
        {"required": False, "nullable": True, "value": ""},
        {"required": False, "nullable": True, "value": "plhome@yandex.ru"},
        {"required": False, "nullable": False, "value": "plhome@yandex.ru"},
        {"required": False, "nullable": False, "value": "123lhome@yan12dex.ru"}
    ])
    def test_email_field_good_value(self, test_case):
        instance = EmailField(required=test_case['required'], nullable=test_case['nullable'])
        self.assertEqual(self.validate_value_for_cls_instance(instance, test_case['value']), True,
                         msg='{}'.format(test_case))

    @cases([
        {"required": False, "nullable": True, "value": 0},
        {"required": False, "nullable": False, "value": ""},
        {"required": False, "nullable": True, "value": "plhome@yandex.ru"},
        {"required": False, "nullable": True, "value": "89354567814"},
        {"required": False, "nullable": True, "value": 89354567814},
        {"required": False, "nullable": True, "value": 893545678111},
        {"required": False, "nullable": True, "value": 8935456781},
        {"required": False, "nullable": True, "value": 793545678111},
        {"required": False, "nullable": True, "value": 7935456781}
    ])
    def test_phone_field_bad_value(self, test_case):
        instance = PhoneField(required=test_case['required'], nullable=test_case['nullable'])
        self.assertEqual(self.validate_value_for_cls_instance(instance, test_case['value']), False,
                         msg='{}'.format(test_case))

    @cases([
        {"required": False, "nullable": True, "value": 79354567814},
        {"required": False, "nullable": True, "value": "79354567814"}
    ])
    def test_phone_field_good_value(self, test_case):
        instance = PhoneField(required=test_case['required'], nullable=test_case['nullable'])
        self.assertEqual(self.validate_value_for_cls_instance(instance, test_case['value']), True,
                         msg='{}'.format(test_case))

    @cases([
        {"required": False, "nullable": True, "value": 0},
        {"required": False, "nullable": False, "value": ""},
        {"required": False, "nullable": True, "value": "plhome@yandex.ru"},
        {"required": False, "nullable": True, "value": "89354567814"},
        {"required": False, "nullable": True, "value": 89354567814},
        {"required": False, "nullable": True, "value": "01.13.1988"},
        {"required": False, "nullable": True, "value": "32.12.1988"},
        {"required": False, "nullable": True, "value": "00.12.1988"},
        {"required": False, "nullable": True, "value": "01.00.1988"},
        {"required": False, "nullable": True, "value": "1988.01.01"},
        {"required": False, "nullable": True, "value": "01.1988.01"}
    ])
    def test_date_field_bad_value(self, test_case):
        instance = DateField(required=test_case['required'], nullable=test_case['nullable'])
        self.assertEqual(self.validate_value_for_cls_instance(instance, test_case['value']), False,
                         msg='{}'.format(test_case))

    @cases([
        {"required": False, "nullable": True, "value": "01.12.1988"},
        {"required": False, "nullable": True, "value": "02.12.1188"},
    ])
    def test_date_field_good_value(self, test_case):
        instance = DateField(required=test_case['required'], nullable=test_case['nullable'])
        self.assertEqual(self.validate_value_for_cls_instance(instance, test_case['value']), True,
                         msg='{}'.format(test_case))

    @cases([
        {"required": False, "nullable": True, "value": 0},
        {"required": False, "nullable": False, "value": ""},
        {"required": False, "nullable": True, "value": "plhome@yandex.ru"},
        {"required": False, "nullable": True, "value": "89354567814"},
        {"required": False, "nullable": True, "value": 89354567814},
        {"required": False, "nullable": True, "value": "01.13.1988"},
        {"required": False, "nullable": True, "value": "32.12.1988"},
        {"required": False, "nullable": True, "value": "00.12.1988"},
        {"required": False, "nullable": True, "value": "01.00.1988"},
        {"required": False, "nullable": True, "value": "1988.01.01"},
        {"required": False, "nullable": True, "value": "01.1988.01"},
        {"required": False, "nullable": True, "value": "01.01.1198"},
        {"required": False, "nullable": True, "value": "01.01.1951"}
    ])
    def test_birthday_field_bad_value(self, test_case):
        instance = BirthDayField(required=test_case['required'], nullable=test_case['nullable'])
        self.assertEqual(self.validate_value_for_cls_instance(instance, test_case['value']), False,
                         msg='{}'.format(test_case))

    @cases([
        {"required": False, "nullable": True, "value": "01.12.1988"},
        {"required": False, "nullable": True, "value": "01.01.1952"}
    ])
    def test_birthday_field_good_value(self, test_case):
        instance = BirthDayField(required=test_case['required'], nullable=test_case['nullable'])
        self.assertEqual(self.validate_value_for_cls_instance(instance, test_case['value']), True,
                         msg='{}'.format(test_case))

    @cases([
        {"required": False, "nullable": True, "value": 3},
        {"required": False, "nullable": True, "value": -1},
        {"required": False, "nullable": True, "value": "1"},
        {"required": False, "nullable": False, "value": ""}
    ])
    def test_gender_field_bad_value(self, test_case):
        instance = GenderField(required=test_case['required'], nullable=test_case['nullable'])
        self.assertEqual(self.validate_value_for_cls_instance(instance, test_case['value']), False,
                         msg='{}'.format(test_case))

    @cases([
        {"required": False, "nullable": True, "value": 0},
        {"required": False, "nullable": True, "value": 1},
        {"required": False, "nullable": True, "value": 2}
    ])
    def test_gender_field_good_value(self, test_case):
        instance = GenderField(required=test_case['required'], nullable=test_case['nullable'])
        self.assertEqual(self.validate_value_for_cls_instance(instance, test_case['value']), True,
                         msg='{}'.format(test_case))

    @cases([
        {"required": False, "nullable": False, "value": [1, "2"]},
        {"required": False, "nullable": True, "value": {}},
        {"required": False, "nullable": True, "value": -1},
        {"required": False, "nullable": True, "value": "1"},
        {"required": False, "nullable": True, "value": ""},
        {"required": False, "nullable": False, "value": []}
    ])
    def test_client_id_field_bad_value(self, test_case):
        instance = ClientIDsField(required=test_case['required'], nullable=test_case['nullable'])
        self.assertEqual(self.validate_value_for_cls_instance(instance, test_case['value']), False,
                         msg='{}'.format(test_case))

    @cases([
        {"required": False, "nullable": True, "value": []},
        {"required": False, "nullable": True, "value": [1, 2]},
        {"required": False, "nullable": False, "value": [1, 2]}
    ])
    def test_client_id_field_good_value(self, test_case):
        instance = ClientIDsField(required=test_case['required'], nullable=test_case['nullable'])
        self.assertEqual(self.validate_value_for_cls_instance(instance, test_case['value']), True,
                         msg='{}'.format(test_case))


if __name__ == "__main__":
    unittest.main()
