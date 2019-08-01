#!/usr/bin/env python
# encoding: utf-8
# learn from https://zhuanlan.zhihu.com/p/40151702

__author__ = 'Sisin'

from urllib import parse
import logging
import requests
import base64
import time 
import json 
import re
import rsa
import binascii

class wbLogin(object):
    def __init__(self, username, password):
        self._username = username
        self._password = password
        self.session = requests.Session()
        logging.debug('initial completed')

    def get_su(self):
        username_quote = parse.quote_plus(self._username)
        # get 'su' by encoding username with base64
        su = base64.b64encode(username_quote.encode("utf-8")).decode("utf-8")
        logging.debug("su is: %s", su)
        return su
    
    def get_prelogin_args(self, su):
        params = {
            "entry": "weibo",
            "callback": "sinaSSOController.preloginCallBack",
            "su": su,
            "rsakt": "mod",
            "checkpin": "1",
            "client": "ssologin.js(v1.4.19)",
            "_": int(time.time()*1000),
        }
        """
        response looks like:
        sinaSSOController.preloginCallBack({
            "retcode":0,
            "servertime":1532035056,
            "pcid":"gz-9fc2b5745f59b8e1a840ca7f98267d025834",
            "nonce":"FLN18Y",
            "pubkey":"EB2A38568661887FA180BDDB5CABD5F21C7BFD59C090CB2D245A87AC253062882729293E5506350508E7F9AA3BB77F4333231490F915F6D63C55FE2F08A49B353F444AD3993CACC02DB784ABBB8E42A9B1BBFFFB38BE18D78E87A0E41B9B8F73A928EE0CCEE1F6739884B9777E4FE9E88A1BBE495927AC4A799B3181D6442443",
            "rsakv":"1330428213",
            "is_openlock":0,
            "lm":1,
            "smsurl":"https:\\/\\/login.sina.com.cn\\/sso\\/msglogin?entry=weibo&mobile=188********&s=e8dd4a85ed986ba69580489723030826",
            "showpin":0,
            "exectime":7
        })
        
        'smsurl' is a url with invalid chars, get rid of those chars by regular expression
        """
        try:
            response = self.session.get("https://login.sina.com.cn/sso/prelogin.php", params=params)
            prelogin_args = json.loads(re.search(r"\((?P<data>.*)\)", response.text).group("data"))
        except Exception as exce:
            prelogin_args = {}
            logging.exception("Get prelogin args error")
        logging.debug("Prelogin args: %s", prelogin_args)
        return prelogin_args

    def get_sp(self, servertime, nonce, pubkey):
        s = (str(servertime) + "\t" + str(nonce) + "\n" + str(self._password)).encode("utf-8")
        public_key = rsa.PublicKey(int(pubkey, 16), int("10001", 16))
        psd = rsa.encrypt(s, public_key)
        sp = binascii.b2a_hex(psd).decode()
        logging.debug("sp is: %s", sp)
        return sp

    def get_postdata(self, su, sp, prelogin_args):
        """
        'su': encoded username,
        'sp': encoded password,
        'servertime', 'nonce', 'rskav': the same as in reponse
        rest parameters are consistent
        """
        postdata = {
            "entry": "weibo",
            "gateway": "1",
            "from": "",
            "savestate": "7",
            "qrcode_flag":'false',
            "useticket": "1",
            "pagerefer": "",
            "vsnf": "1",
            "su": su,
            "service": "miniblog",
            "servertime": prelogin_args['servertime'],
            "nonce": prelogin_args['nonce'],
            "pwencode": "rsa2",
            "rsakv": prelogin_args['rsakv'],
            "sp": sp,
            "sr": "1366*768",
            "encoding": "UTF-8",
            "prelt": "1085",
            "url": "https://www.weibo.com/ajaxlogin.php?framelogin=1&callback=parent.sinaSSOController.feedBackUrlCallBack",
            "returntype": "META"
        }
        if "showpin" in prelogin_args.keys():
            if prelogin_args["showpin"] == 1:
                pin_url = "https://login.sina.com.cn/cgi/pin.php?r=%s&s=0&p=%s" % (int(time.time()*1000), prelogin_args["pcid"])
                # if verification code, two more parameters--'pcid' & 'door'
                # pcid is the same as prelogin_args
                # door is the verification code that we input
                try:
                    pic = self.session.get(pin_url).content
                except Exception as exce:
                    pic = b''
                    logging.exception("Get pin error")
                with open("pin.png", "wb") as file_out:
                    file_out.write(pic)
                code = input("请输入验证码:")
                postdata["pcid"] = prelogin_args["pcid"]
                postdata["door"] = code

        logging.debug("Postdata is: %s", postdata)
        return postdata

    def login(self):
        self.session.headers.update({'User-Agent':'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36 Core/1.53.4482.400 QQBrowser/9.7.13001.400'})
        self.su = self.get_su()
        self.prelogin_args = self.get_prelogin_args(self.su)
        if not self.prelogin_args:
            logging.debug("Weibo prelogin fail!")
        else:
            self.sp = self.get_sp(self.prelogin_args["servertime"], self.prelogin_args["nonce"], self.prelogin_args["pubkey"])
            self.postdata = self.get_postdata(self.su, self.sp, self.prelogin_args)
            login_url = "http://login.sina.com.cn/sso/login.php?client=ssologin.js(v1.4.19)"
            try:
                login_page = self.session.post(login_url, data=self.postdata)
            except Exception as exce:
                logging.exception("Get login page error")
                return False
            login_redirect = login_page.content.decode("GBK")
            pa = r'location\.replace\([\'"](.*?)[\'"]\)'
            redirect_url = re.findall(pa, login_redirect)[0]
            try:
                login_index = self.session.get(redirect_url)
            except Exception as exce:
                logging.exception("Get login index error")
                return False
            try:
                result = json.loads(re.search(r"\((?P<data>.*)\)", login_index.text).group('data'))
                if result['result']:
                    logging.debug("Weibo login success!")
                    return True
                else:
                    logging.debug("Weibo login fail!")
                    return False
            except Exception as exec:
                logging.debug("Weibo login fail!")
                return False

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format="%(asctime)s\t%(levelname)s\t%(message)s")
    user = ''
    psd = ''
    user = wbLogin(username=user, password=psd)
    user.login()