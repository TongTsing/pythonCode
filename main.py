#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
import math
import urllib
import json
import hashlib
import hmac

import urllib.request
import urllib.parse

__auther__ = 'lightjiao'

'''
带签名加密的OpenAPI请求方法
'''


class EasyRequest(object):
    ACCESS_KEY = ''
    SECRET_KEY = ''
    IP = ''

    def __init__(self, headers=None, method=None, url=None, data=None, params=None):
        if headers is None:
            headers = {}
        if method is None:
            method = ''
        if url is None:
            url = ''
        if data is None:
            data = {}
        if params is None:
            params = {}

        self.headers = headers
        self.__method = method
        self.__url = url
        self.__data = data
        self.params = params
        self.signature_params = {}

        # 设置访问的 Host
        self.set_header('Host', 'openapi.easyops-only.com')

    @property
    def method(self):
        return self.__method

    @method.setter
    def method(self, method):
        self.__method = method.upper()

    @classmethod
    def is_json(cls, jsondata):
        try:
            json.loads(jsondata)
        except json.JSONDecodeError:
            return False
        return True

    @property
    def data(self):
        return self.__data

    '''
    以list 或者 dict 格式的数据类型设置请求data
    '''

    @data.setter
    def data(self, data):
        if not isinstance(data, dict) and not isinstance(data, list):
            raise ValueError("set data failed: argument shoule be a dict or a list for json_dumps")
        else:
            self.__data = data

    @property
    def jsondata(self):
        return json.dumps(self.__data)

    '''
    以Json字符串的格式设置请求data
    '''

    @jsondata.setter
    def jsondata(self, jsondata):
        if not EasyRequest.is_json(jsondata):
            raise ValueError("set jsondata failed: argument should be an valid json string")
        else:
            self.__data = json.loads(jsondata)

    def get_header(self, key):
        if key in self.headers:
            return self.headers[key]
        return None

    def set_header(self, key, value):
        self.headers[key] = value
        return self

    def set_param(self, key, value):
        self.params[key] = value
        print("line105------")
        print(self.params)
        return self

    @property
    def url(self):
        return self.__url

    @url.setter
    def url(self, url):
        if url.startswith('/'):
            self.__url = 'http://' + EasyRequest.IP + url
        else:
            self.__url = 'http://' + EasyRequest.IP + '/' + url
        print(self.__url)

    def send(self):
        # return EasyCurl.send_request(self.signature(str(math.trunc(time.time()))))
        return EasyCurl.send_request(self.signature("1666085979"))
    def __get_url_path(self):
        o = urllib.parse.urlparse(self.url)
        print("o.path+++++++")
        print(o.path)
        return o.path

    def build_url(self):
        parts = urllib.parse.urlparse(self.url)

        query_string = ''
        param = dict(self.params, **self.signature_params)

        if len(parts.query) > 0:
            query_string += parts.query + '&' + '&'.join(['%s=%s' % (k, v) for k, v in param.items()])
        else:
            query_string += '&'.join(['%s=%s' % (k, v) for k, v in param.items()])

        ret_url = parts.scheme + '://' + parts.netloc

        if len(parts.path) > 0:
            ret_url += parts.path

        if query_string:
            ret_url += '?' + query_string
        print("rest_url-------")
        print(ret_url)
        return ret_url

    def signature(self, request_time):

        if self.__method == 'POST' or self.__method == 'PUT':
            self.set_header('Content-Type', 'application/json')
            content_type = self.get_header('Content-Type')

        else:
            self.set_header('Content-Type', '')
            self.headers.pop('Content-Type')
            content_type = ''

        url_param = ''.join(['%s%s' % (k, self.params[k]) for k in sorted(self.params.keys())])
        print("line 163 ---- urlparam")
        print(url_param)
        content_md5 = ''
        if self.method == 'POST' or self.method == 'PUT':
            md5 = hashlib.md5()
            md5.update(json.dumps(self.data).encode('utf-8'))
            content_md5 = md5.hexdigest()

        url_path = self.__get_url_path()
        string_to_signaure = "\n".join([
            self.method,
            url_path,
            url_param,
            content_type,
            content_md5,
            request_time,
            EasyRequest.ACCESS_KEY]
        ).encode()
        print("line182-----------")
        print(string_to_signaure)
        s = EasyRequest.SECRET_KEY.encode()
        self.signature_params['accesskey'] = EasyRequest.ACCESS_KEY
        self.signature_params['signature'] = hmac.new(s, string_to_signaure, hashlib.sha1).hexdigest()
        print(self.signature_params["signature"])
        self.signature_params['expires'] = request_time

        return self


class EasyCurl(object):

    @classmethod
    def parse_request(cls, request):
        url_request = urllib.request.Request(url=request.build_url(), headers=request.headers, method=request.method)
        if request.method == 'POST' or request.method == 'PUT':
            url_request.data = request.jsondata.encode()

        return url_request

    @classmethod
    def send_request(cls, request):
        req = EasyCurl.parse_request(request)

        try:
            ''' HTTPResponse Objects '''
            response = urllib.request.urlopen(req, timeout=30)
            return EasyResponse(response.status, response.getheaders(), response.read().decode())

        except Exception as e:
            code = -1
            if hasattr(e, 'code'):
                code = e.code
            headers = {}
            if hasattr(e, 'headers'):
                headers = e.headers
            reason = ''
            if hasattr(e, 'reason'):
                reason = e.reason

            return EasyResponse(code, headers, reason)


class EasyResponse(object):
    def __init__(self, code, headers, info=''):
        self.code = code
        self.headers = self.parse_headers(headers, code)
        self.info = info

    @classmethod
    def parse_headers(cls, headers, code):
        new_headers = {}
        if code != 200:
            for key, value in headers.items():
                new_headers[key] = value
        else:
            for key, value in headers:
                new_headers[key] = value

        return new_headers

'''
测试用例代码
'''


# 打印请求结果
def __test_print_result(request):
    # 发送请求
    result = request.send()

    # 获取请求结果，请求成功时，code = 200
    print(result.code)

    # 获取请求结果信息，测试URL请求成功时， info = Signature success!
    print(result.info)
    # print(result.headers)


# POST测试方法
def __test_post(request):
    # 设置请求类型
    request.method = 'POST'

    # 设置请求的 url，此处为测试用URL接口
    request.url = 'cmdbservice/v2/object/HOST/instance'

    # 设置请求消息内容，格式举例如下，可以是纯Json字符串， 也可以为dic 或者 list 数据类型
    # request.data = {"id":123, "name":"jack"} #example_1
    # request.jsondata = "[]"     #example_2
    b=json.dumps({'hostname': 'tq', 'ip': '192.168.110.173'})
    request.jsondata = b

    __test_print_result(request)

# GET测试方法


def __test_get(request):
    request.method = 'GET'
    request.url = 'cmdbservice/object/HOST/instance/5de9fa2561eed'

    # 设置请求参数
    request.set_param('page', 1).set_param('pageSize', 30)
    __test_print_result(request)


# PUT测试方法
def __test_put(request):
    request.method = 'PUT'
    request.url = 'cmdb/test/json'
    request.data = {"id": 123, "name": "jack"}
    __test_print_result(request)


# DELETE测试方法
def __test_delete(request):
    request.method = 'DELETE'
    request.url = 'cmdb/test'
    __test_print_result(request)


if __name__ == '__main__':
    # 设置accesskey 和 secretkey
    EasyRequest.ACCESS_KEY = 'fe5ea7b520d1f0e7ae6ab0c8'
    EasyRequest.SECRET_KEY = '65514d4f4447446d447a52576e595351626f794b4d566a4c4a77486c697a424b'
    EasyRequest.IP = '192.168.110.169'

    request = EasyRequest()

    __test_get(request)
    # __test_delete(request)
    # __test_put(request)
    # __test_get(request)
