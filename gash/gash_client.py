# -*- coding: utf-8 -*-

import logging
import base64
from hashlib import sha1

import requests
from crypt3des import Crypt3Des
from .utils import dict2xml, xml2dict

logger = logging.getLogger('gash')


class GashClient(object):
    """
    一个gash的client
    """

    password = None
    key = None
    iv = None

    def __init__(self, password, key, iv):
        """
        key
        """

        self.password = password
        self.key = key
        self.iv = iv

    def post(self, url, data):
        """
        调用接口
        """
        if not isinstance(data, dict):
            logger.fatal('data is not dict. %s', data)
            return None, 'invalid data'

        # 就算有也不能存
        data.pop('ERQC', None)

        data['ERQC'] = self._make_erqc(
            data['CID'],
            data['COID'],
            data['CUID'],
            data['AMOUNT'],
        )

        rsp = requests.post(url, self.make_req(data))

        if rsp.status_code != 200:
            logger.fatal('status_code: %s, data:%s', rsp.status_code, data)
            return None, 'status_code is %s' % rsp.status_code

        try:
            return self.parse_rsp(rsp.text), None
        except Exception, e:
            logger.fatal('e: %s, data: %s', e, data, exc_info=True)
            return None, str(e)

    def make_req(self, data):
        return base64.encodestring(dict2xml(data))

    def parse_rsp(self, data):
        return xml2dict(base64.decodestring(data))

    def _make_erqc(self, cid, coid, cuid, amt):
        """
        生成ERQC
        """

        # 因为担心可能只能用一次
        des = Crypt3Des(self.key, self.iv)

        src = '%s%s%s%s%s' % (cid, coid, cuid, amt, self.password)

        result = des.encrypt(src)
        # 20字符的2进制
        result = sha1(result).digest()

        result = base64.encodestring(result)

        return result
