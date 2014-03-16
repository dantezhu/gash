# -*- coding: utf-8 -*-

import base64
from Crypto.Cipher import DES3


class Crypt3Des(object):
    """
    用3DES加密
    """

    cipher = None

    def __init__(self, key, iv):
        # 其实按理说不该在这里做decode，但是php的代码里是这么写的，我们就这么用吧
        key = base64.decodestring(key)
        iv = base64.decodestring(iv)

        self.cipher = DES3.DES3Cipher(key=key, iv=iv, model=DES3.MODE_CBC)

    def encrypt(self, src):
        """
        加密操作
        """
        padding_src = self.padding_pkc_s7(src)

        return self.cipher.encrypt(padding_src)

    def padding_pkc_s7(self, src):
        """
        补齐
        """

        remain_len = len(src) % self.cipher.block_size

        if remain_len == 0:
            return

        else:
            return '%s%s' % (src, chr(remain_len)*remain_len)
