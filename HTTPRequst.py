import requests
import os
from urllib import request as req
import urllib3 as req3
import ssl
from urllib3.poolmanager import PoolManager
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util import ssl_
from http.client import HTTPSConnection
from requests_toolbelt import SSLAdapter
import logging
import warnings
from enum import Enum


CIPHERS = (
    'ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:AES256-SHA'
)

class SelectTypeRequst(Enum):
    """Набор Команды"""
    DATA = 0,
    JSON = 1


class Myadapter(HTTPAdapter):
    def init_poolmanager(self, connections, maxsize, block=False):
        """Create and initialize the urllib3 PoolManager."""
        self.poolmanager = PoolManager(
            num_pools=connections, maxsize=maxsize,
            block=block, ssl_version=ssl.PROTOCOL_SSLv23)

class TlsAdapter(HTTPAdapter):
    def __init__(self, ssl_options=0, **kwargs):
        self.ssl_options = ssl_options
        super(TlsAdapter, self).__init__(**kwargs)

    def init_poolmanager(self, *pool_args, **pool_kwargs):
        ctx = ssl_.create_urllib3_context(ciphers=CIPHERS, cert_reqs=ssl.CERT_REQUIRED, options=self.ssl_options)
        self.poolmanager = PoolManager(*pool_args,
                                       ssl_context=ctx,
                                       **pool_kwargs)

class Ssl23HttpAdapter(HTTPAdapter):
    """"Transport adapter" that allows us to use SSLv3."""
    def init_poolmanager(self, connections, maxsize, block=False):
        """Иницелизация доступа"""
        self.poolmanager = PoolManager(
            num_pools=connections, maxsize=maxsize,
            block=block, ssl_version=ssl.PROTOCOL_SSLv23 )
class TLS12HttpAdapter(HTTPAdapter):
    """"Transport adapter" that allows us to use SSLv3."""
    def init_poolmanager(self, connections, maxsize, block=False):
        """Иницелизация доступа"""
        self.poolmanager = PoolManager(
            num_pools=connections, maxsize=maxsize,
            block=block, ssl_version=ssl.PROTOCOL_TLSv1_2 )

class ForceTLSV1Adapter(HTTPAdapter):
    """Require TLSv1 for the connection"""
    def init_poolmanager(self, connections, maxsize, block=False):
        # This method gets called when there's no proxy.
        self.poolmanager = PoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            ssl_version=ssl.PROTOCOL_TLSv1,
        )

    def proxy_manager_for(self, proxy, **proxy_kwargs):
        # This method is called when there is a proxy.
        proxy_kwargs['ssl_version'] = ssl.PROTOCOL_TLSv1
        return super(ForceTLSV1Adapter, self).proxy_manager_for(proxy, **proxy_kwargs)

class INTERNET_RES:
    """Наличие Интернета"""
    def IsConnected(Timeout=0):
        """Наличие Интернета True/False"""
        url="http://google.com"
        try:
            if Timeout > 0:
                # If you want you can add the timeout parameter to filter slower connections. i.e. urllib.request.urlopen('http://google.com', timeout=5)
                req.urlopen(url,timeout=Timeout)
            else:
                req.urlopen(url)
            return True
        except:
            return False
class HTTP:
    def GET(self,Url,Timeout=0, Headers={}, Cookies={}, SertVer=False):
        res = ResponseResult()
        try:
            session_req = requests.Session()
            session_req.verify = SertVer  # False отказ проверки сертификата
            session_req.mount("https://", SSLAdapter(ssl.PROTOCOL_SSLv23))
            requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

            res_resp = None
            if Timeout > 0:
                res_resp = session_req.get(Url, timeout=Timeout, headers=Headers, cookies=Cookies)
            if Timeout <= 0:
                res_resp = session_req.get(Url, headers=Headers, cookies=Cookies)
            # Статусы кода ответа
            res.Response = res_resp
            if res_resp.status_code == 200:
                res.StatusCode = res_resp.status_code
                res.Content = res_resp.text
                res.IsSuccess = True
            if res_resp.status_code != 200:
                res.StatusCode = res_resp.status_code
        except Exception as ex:
            res.ERROR = f"ERROR: {ex}!"
        return res
    def POST(self,Url,Select=SelectTypeRequst.DATA.name, Data={}, Timeout=0, Headers={}, Cookies={},SertVer=False):
        res = ResponseResult()
        try:
            session_req = requests.Session()
            session_req.verify = SertVer  # False отказ проверки сертификата
            session_req.mount("https://", SSLAdapter(ssl.PROTOCOL_SSLv23))
            requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

            res_resp = None
            if Select.lower()==SelectTypeRequst.DATA.name.lower():
                if Timeout > 0:
                    res_resp = session_req.post(Url,data=Data, timeout=Timeout, headers=Headers, cookies=Cookies)
                    print(res_resp)
                if Timeout <= 0:
                    res_resp = session_req.post(Url,data=Data, headers=Headers, cookies=Cookies)
                    print(res_resp)
                # Статусы кода ответа
                res.Response = res_resp
                if res_resp.status_code == 200:
                    res.StatusCode = res_resp.status_code
                    res.Content = res_resp.text
                    res.IsSuccess = True
                if res_resp.status_code != 200:
                    res.StatusCode = res_resp.status_code
            if Select.lower()==SelectTypeRequst.JSON.name.lower():
                if Timeout > 0:
                    res_resp = session_req.post(Url,json=Data, timeout=Timeout, headers=Headers, cookies=Cookies)
                    print(res_resp)
                if Timeout <= 0:
                    res_resp = session_req.post(Url,json=Data, headers=Headers, cookies=Cookies)
                    print(res_resp)
                # Статусы кода ответа
                res.Response = res_resp
                if res_resp.status_code == 200:
                    res.StatusCode = res_resp.status_code
                    res.Content = res_resp.text
                    res.IsSuccess = True
                if res_resp.status_code != 200:
                    res.StatusCode = res_resp.status_code
        except Exception as ex:
            res.ERROR = f"ERROR: {ex}!"
        return res
    def DELETE(self,Url,Select=SelectTypeRequst.DATA.name, Data={}, Timeout=0, Headers={}, Cookies={},SertVer=False):
        res = ResponseResult()
        try:
            session_req = requests.Session()
            session_req.verify = SertVer  # False отказ проверки сертификата
            session_req.mount("https://", SSLAdapter(ssl.PROTOCOL_SSLv23))
            requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

            res_resp = None
            if Select.lower()==SelectTypeRequst.DATA.name.lower():
                if Timeout > 0:
                    res_resp = session_req.delete(Url,data=Data, timeout=Timeout, headers=Headers, cookies=Cookies)
                    print(res_resp)
                if Timeout <= 0:
                    res_resp = session_req.delete(Url,data=Data, headers=Headers, cookies=Cookies)
                    print(res_resp)
                # Статусы кода ответа
                res.Response = res_resp
                if res_resp.status_code == 200:
                    res.StatusCode = res_resp.status_code
                    res.Content = res_resp.text
                    res.IsSuccess = True
                if res_resp.status_code != 200:
                    res.StatusCode = res_resp.status_code
            if Select.lower()==SelectTypeRequst.JSON.name.lower():
                if Timeout > 0:
                    res_resp = session_req.delete(Url,json=Data, timeout=Timeout, headers=Headers, cookies=Cookies)
                    print(res_resp)
                if Timeout <= 0:
                    res_resp = session_req.delete(Url,json=Data, headers=Headers, cookies=Cookies)
                    print(res_resp)
                # Статусы кода ответа
                res.Response = res_resp
                if res_resp.status_code == 200:
                    res.StatusCode = res_resp.status_code
                    res.Content = res_resp.text
                    res.IsSuccess = True
                if res_resp.status_code != 200:
                    res.StatusCode = res_resp.status_code
        except Exception as ex:
            res.ERROR = f"ERROR: {ex}!"
        return res

    def UPDATE(self,Url,Select=SelectTypeRequst.DATA.name, Data={}, Timeout=0, Headers={}, Cookies={},SertVer=False):
        res = ResponseResult()
        try:
            session_req = requests.Session()
            session_req.verify = SertVer  # False отказ проверки сертификата
            session_req.mount("https://", SSLAdapter(ssl.PROTOCOL_SSLv23))
            requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

            res_resp = None
            if Select.lower()==SelectTypeRequst.DATA.name.lower():
                if Timeout > 0:
                    res_resp = session_req.request("PUT", Url, data=Data, timeout=Timeout, headers=Headers, cookies=Cookies)
                    print(res_resp)
                if Timeout <= 0:
                    res_resp = session_req.request("PUT", Url, data=Data, headers=Headers, cookies=Cookies)
                    print(res_resp)
                # Статусы кода ответа
                res.Response = res_resp
                if res_resp.status_code == 200:
                    res.StatusCode = res_resp.status_code
                    res.Content = res_resp.text
                    res.IsSuccess = True
                if res_resp.status_code != 200:
                    res.StatusCode = res_resp.status_code
            if Select.lower()==SelectTypeRequst.JSON.name.lower():
                if Timeout > 0:
                    res_resp = session_req.request("PUT", Url, json=Data, timeout=Timeout, headers=Headers, cookies=Cookies)
                    print(res_resp)
                if Timeout <= 0:
                    res_resp = session_req.request("PUT", Url, json=Data, headers=Headers, cookies=Cookies)
                    print(res_resp)
                # Статусы кода ответа
                res.Response = res_resp
                if res_resp.status_code == 200:
                    res.StatusCode = res_resp.status_code
                    res.Content = res_resp.text
                    res.IsSuccess = True
                if res_resp.status_code != 200:
                    res.StatusCode = res_resp.status_code
        except Exception as ex:
            res.ERROR = f"ERROR: {ex}!"
        return res

class HTTP_Proxy:
    def GET(self,Url,ProxyIP, ProxyPort,Timeout=0, Headers={}, Cookies={},SertVer=False):
        """Получение Данных Прокси"""
        res = ResponseResult()
        try:
            proxy_dict={
                "http": f"http://{ProxyIP}:{ProxyPort}",
                "https": f"http://{ProxyIP}:{ProxyPort}"
            }
            #print(f"Прокси Конс: {proxy_dict}")
            session_req = requests.Session()
            session_req.verify = True #False отказ проверки сертификата
            #adapter_SSL23, adapter_TLS12 = Ssl23HttpAdapter(),TLS12HttpAdapter()
            adapter = Myadapter()
            #adapter = TlsAdapter(ssl.PROTOCOL_TLSv1_2 | ssl.PROTOCOL_SSLv23)
            #session_req.mount("http://", SSLAdapter(ssl.PROTOCOL_SSLv23))
            session_req.mount("https://", SSLAdapter(ssl.PROTOCOL_SSLv23))
            session_req.proxies.update(proxy_dict)
            requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

            res_resp = None
            if Timeout>0:
                res_resp = session_req.get(Url, timeout=Timeout, headers=Headers, cookies=Cookies)
            if Timeout<=0:
                res_resp = session_req.get(Url, headers=Headers, cookies=Cookies)
            # Статусы кода ответа
            res.Response = res_resp 
            if res_resp.status_code==200:
                res.StatusCode = res_resp.status_code
                res.Content = res_resp.text
                res.ProxyIP = ProxyIP
                res.ProxyPort = ProxyPort
                res.ProxyFlag = True
                res.IsSuccess = True
                res_resp.close()
            if res_resp.status_code!=200:
                res.StatusCode = res_resp.status_code
        except Exception as ex:
            res.ERROR = f"ERROR: {ex}!"
        return res

    def POST(self, Url,ProxyIP, ProxyPort,Timeout=0, Data={}, Headers={}, Cookies={}, SertVer=False):
        """Прокси Отправка Данных"""
        res = ResponseResult()
        res = ResponseResult()
        try:
            proxy_dict = {
                "http": f"http://{ProxyIP}:{ProxyPort}",
                "https": f"http://{ProxyIP}:{ProxyPort}"
            }
            #print(f"Прокси Конс: {proxy_dict}")
            session_req = requests.Session()
            session_req.verify = True  # False отказ проверки сертификата
            # adapter_SSL23, adapter_TLS12 = Ssl23HttpAdapter(),TLS12HttpAdapter()
            adapter = Myadapter()
            # adapter = TlsAdapter(ssl.PROTOCOL_TLSv1_2 | ssl.PROTOCOL_SSLv23)
            # session_req.mount("http://", SSLAdapter(ssl.PROTOCOL_SSLv23))
            session_req.mount("https://", SSLAdapter(ssl.PROTOCOL_SSLv23))
            session_req.proxies.update(proxy_dict)
            requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

            res_resp = None
            if Select.lower()==SelectTypeRequst.DATA.name.lower():
                if Timeout > 0:
                    res_resp = session_req.post(Url, data=Data, timeout=Timeout, headers=Headers, cookies=Cookies)
                if Timeout <= 0:
                    res_resp = session_req.post(Url, data=Data, headers=Headers, cookies=Cookies)
                # Статусы кода ответа
                res.Response = res_resp
                if res_resp.status_code == 200:
                    res.StatusCode = res_resp.status_code
                    res.Content = res_resp.text
                    res.ProxyIP = ProxyIP
                    res.ProxyPort = ProxyPort
                    res.ProxyFlag = True
                    res.IsSuccess = True
                    res_resp.close()
                if res_resp.status_code != 200:
                    res.StatusCode = res_resp.status_code
            if Select.lower()==SelectTypeRequst.JSON.name.lower():
                if Timeout > 0:
                    res_resp = session_req.post(Url, json=Data, timeout=Timeout, headers=Headers, cookies=Cookies)
                if Timeout <= 0:
                    res_resp = session_req.post(Url, json=Data, headers=Headers, cookies=Cookies)
                # Статусы кода ответа
                res.Response = res_resp
                if res_resp.status_code == 200:
                    res.StatusCode = res_resp.status_code
                    res.Content = res_resp.text
                    res.ProxyIP = ProxyIP
                    res.ProxyPort = ProxyPort
                    res.ProxyFlag = True
                    res.IsSuccess = True
                    res_resp.close()
                if res_resp.status_code != 200:
                    res.StatusCode = res_resp.status_code
        except Exception as ex:
            res.ERROR = f"ERROR: {ex}!"
        return res

class ResponseResult(object):
    """Результаты Ответа Запроса"""
    StatusCode = 429
    """Контент"""
    Content = ""
    """Результаты JSONResult"""
    IsSuccess = False
    """Ошибка"""
    ERROR = ""
    """Использован Прокси True/False Нет"""
    ProxyFlag = False
    """Прокси Протокол"""
    ProxyProtocol = ""
    """Прокси IP"""
    ProxyIP = ""
    """Прокси Порт"""
    ProxyPort = 80
    """Вся Информация"""
    Response =""

class ProxyInfo(object):
    """Прокси Обьект"""
    IP=""
    """Порт"""
    PORT=80
    def __init__(self, _IP="", _PORT=80):
        super(ProxyInfo, self).__init__()
        self.IP=_IP
        self.PORT=_PORT