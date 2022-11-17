# encoding=utf-8

import collections
from pprint import pprint
import requests
import copy
import base64
import xmltodict
import os
from suds.client import Client
import smtplib
from email.header import Header
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
import json
import sys
import hashlib
import hmac

reload(sys)
sys.setdefaultencoding('utf8')
import pandas as pd

ask = "e72d85ed71b5d64895981d17"
ssk = "4e7367746c61767568794248667a436e677555796b4c5449786553446c665447"
cmdb_host = "10.2.239.45"


def fmt_print(msg, is_title=False):
    if is_title:
        print
        u"======================================================================="
        print
        msg
        print
        u"======================================================================="
    else:
        print
        msg


# 导出excel
def importExcel(objectId, queryData):
    print("-----importExcel()-------")
    print("导出的excel在/tmp/shujv.xlsx")
    headers = {
        "org": "3103",
        "user": "easyops",
        "host": "cmdb_resource.easyops-only.com",
        "content-type": "application/json"
    }
    # url = "http://{CMDB_HOST}/export/object/{objectId}/instance/excel".format(CMDB_HOST="10.0.241.159", objectId=objectId)

    res = do_requests(url="/cmdb_resource/export/object/{objectId}/instance/excel".format(objectId=objectId),
                      data=queryData)
    with open("/tmp/shujv.xlsx", "wb+") as f:
        f.write(res.content)
    print("-----------importExcel ended--------")


# mail

def mailWithFile(filePath):
    sender = 'cmdb'
    password = "AXcm20@2088"
    receivers = ['jiangzy1@essence.com.cn']  # 接收邮件，可设置为你的QQ邮箱或者其他邮箱

    # 创建一个带附件的实例
    message = MIMEMultipart()
    message['From'] = Header("CMDB邮件通知", 'utf-8')
    message['To'] = Header("系统保障等级不规范通知", 'utf-8')
    subject = '系统保障等级不规范通知'
    message['Subject'] = Header(subject, 'utf-8')

    # 邮件正文内容
    message.attach(MIMEText('系统保障等级不规范的系统的EXCEL表', 'plain', 'utf-8'))

    # 构造附件1，传送当前目录下的 test.txt 文件
    att1 = MIMEText(open(filePath, 'rb').read(), 'base64', 'utf-8')
    att1["Content-Type"] = 'application/octet-stream'
    # 这里的filename可以任意写，写什么名字，邮件中显示什么名字
    att1["Content-Disposition"] = 'attachment; filename="不规范系统.excel"'
    message.attach(att1)

    try:
        smtpObj = smtplib.SMTP()
        smtpObj.login(sender, password)
        smtpObj.connect(smtpserver)
        smtpObj.sendmail(sender, receivers, message.as_string())
        print("邮件发送成功")
    except smtplib.SMTPException:
        print("Error: 无法发送邮件")


def html_mail(asset_list):
    q_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    asset = json.loads(asset_list)
    assets = pd.DataFrame(asset)
    df_html = assets.to_html(escape=False)  # DataFrame数据转化为HTML表格形式
    head = \
        """
        <head>
            <meta charset="utf-8">
            <STYLE TYPE="text/css" MEDIA=screen>

                table.dataframe {
                    border-collapse: collapse;
                    border: 2px solid #a19da2;
                    /*居中显示整个表格*/
                    margin: auto;
                }

                table.dataframe thead {
                    border: 2px solid #91c6e1;
                    background: #f1f1f1;
                    padding: 10px 10px 10px 10px;
                    color: #333333;
                }

                table.dataframe tbody {
                    border: 2px solid #91c6e1;
                    padding: 10px 10px 10px 10px;
                }

                table.dataframe tr {

                }

                table.dataframe th {
                    vertical-align: top;
                    font-size: 14px;
                    padding: 10px 10px 10px 10px;
                    color: #105de3;
                    font-family: arial;
                    text-align: center;
                }

                table.dataframe td {
                    text-align: center;
                    padding: 10px 10px 10px 10px;
                }

                body {
                    font-family: 宋体;
                }

                h1 {
                    color: #5db446
                }

                div.header h2 {
                    color: #0002e3;
                    font-family: 黑体;
                }

                div.content h2 {
                    text-align: center;
                    font-size: 28px;
                    text-shadow: 2px 2px 1px #de4040;
                    color: #fff;
                    font-weight: bold;
                    background-color: #008eb7;
                    line-height: 1.5;
                    margin: 20px 0;
                    box-shadow: 10px 10px 5px #888888;
                    border-radius: 5px;
                }

                h3 {
                    font-size: 22px;
                    background-color: rgba(0, 2, 227, 0.71);
                    text-shadow: 2px 2px 1px #de4040;
                    color: rgba(239, 241, 234, 0.99);
                    line-height: 1.5;
                }

                h4 {
                    color: #e10092;
                    font-family: 楷体;
                    font-size: 20px;
                    text-align: center;
                }

                td img {
                    /*width: 60px;*/
                    max-width: 300px;
                    max-height: 300px;
                }

            </STYLE>
        </head>
        """
    body = \
        """
        <body>

        <div align="center" class="header">
            <!--标题部分的信息-->
            <h1 align="center">保障等级不合规业务系统通知</h1>
            <a href="https://cmdb.essence.com.cn/next/next-cmdb-instance-management/next/BUSINESS/list" target="_blank" rel="noopener noreferrer">查看系统清单</a>
        </div>

        <hr>

        <div class="content">
            <!--正文内容-->
            <h2> </h2>

            <div>
                <h4></h4>
                {df_html}

            </div>
            <hr>

            <p style="text-align: center">

            </p>
        </div>
        </body>
        """.format(yesterday=q_time, df_html=df_html)
    html_msg = "<html>" + head + body + "</html>"
    html_msg = html_msg.replace('\n', '').encode("utf-8")
    return html_msg


def mail_test(msg_content, receiver):
    ret = True
    # 用户名
    sender = 'cmdb'
    # 接收方
    # receiver = ['jiangzy1@essence.com.cn']
    # receiver = 'jiangzy1@essence.com.cn,yebf@essence.com.cn'
    # receiver = receiver
    # 主题
    subject = '保障等级合规性检查'
    # 服务器地址
    smtpserver = '10.5.161.12:25'
    # 登录名，必须与发送用户一致，否则会报错
    username = 'cmdb'
    # 授权码
    password = 'AXcm20@2088'
    # 发送内容
    mail_body = msg_content
    #
    msg = MIMEText(mail_body, 'html', 'utf-8')
    msg["Subject"] = subject
    # msg['Subject'] = Header(subject, 'utf-8')
    msg['Form'] = sender
    msg['To'] = ",".join(receiver)
    try:
        # 调用smtplib模块进行发送
        smtp = smtplib.SMTP()
        smtp.connect(smtpserver)
        smtp.login(username, password)
        smtp.sendmail(sender, msg['To'].split(','), msg.as_string())
        print
        "test:", msg['To'].split(',')

        smtp.quit()
        print('sendemail successful!')
    except Exception as e:
        print('sendemail failed next is the reason')
        print(e)
        ret = False
    return ret


# 生成cmdb openAPI接口签名, HMAC加密
def create_cmdb_sig(method, url, data):
    # 信息预处理
    method = method.upper()
    m = hashlib.md5()
    m.update(json.dumps(data).encode("utf-8"))
    content = m.hexdigest()
    a = ''
    req_time = str(int(time.time()))
    # 信息拼接
    fields = "\n".join(
        [method,
         url,
         a,
         "application/json",
         content,
         req_time,
         ask]
    )

    # hmac加密
    signature = hmac.new(ssk, fields, hashlib.sha1).hexdigest()

    return signature, "%s?accesskey=%s&expires=%s&signature=%s" % (url, ask, req_time, signature)


# 发起请求
def do_requests(url, data={}):
    method = "post"
    # 获取签名
    sig, url = create_cmdb_sig(method, url, data)
    url_ = "http://%s%s" % (cmdb_host, url)
    headers = {"Content-Type": "application/json", "host": "openapi.easyops-only.com"}
    try:
        r = requests.request(url=url_, method=method, headers=headers, timeout=20, json=data, verify=False)
        if r.status_code == 200:
            if r.json().get("code", 1) == 0 or r.json().get("statuscode", 1) == 0:
                # fmt_print("请求成功")
                return r
        fmt_print("请求失败")
        fmt_print(r.text)
    except Exception as e:
        fmt_print("请求异常")
        fmt_print(e)


def leveltrans(level):
    if level == "A1":
        return 8
    elif level == "A2":
        return 7
    elif level == "B4":
        return 6
    elif level == "B3":
        return 5
    elif level == "B2":
        return 4
    elif level == "B1":
        return 3
    elif level == "C":
        return 2
    elif level == "D":
        return 1
    else:
        return 1


def getMaxLevel(rawLevel, data):
    # data是下游系统的信息
    lvList = []
    lv = -2
    maxlv = -1
    for i in data:
        lv = leveltrans(i["level"])
        # if tmplv > lv:
        #     lv = tmplv
        if lv > leveltrans(rawLevel):
            lvList.append({i["name"]: i["level"]})
        if lv > maxlv:
            maxlv = lv
    return maxlv, lvList


def checkInstance(objectId, queryData):
    tmpDict = {}
    headers = {"user": "easyops", "org": str(EASYOPS_ORG), "content-type": "application/json",
               "host": "cmdb_resource.easyops-only.com"}
    # url = "http://{HOST}/object/{objectId}/instance/_search".format(HOST=EASYOPS_CMDB_HOST.split(":")[0], objectId=objectId)
    # res = requests.post(url=url, headers=headers, json=queryData)
    res = do_requests(url="/cmdb_resource/object/{objectId}/instance/_search".format(objectId=objectId), data=queryData)
    total = res.json()["data"]["total"]
    if total < queryData["page_size"] * ((queryData["page"] - 1)):
        # print("page over")
        return ["break"], ["None"]
    instanceList = []
    if not res.json():
        print("None Type")
        return
    for i in res.json()["data"]["list"]:
        clushBusinfo = []
        if (len(i["BUSINESS1"]) == 0 and len(i["BUSINESS2"]) == 0):
            continue
        if (len(i["BUSINESS2"]) != 0):
            xiayouLv, clushBusinfo = getMaxLevel(i["level"], i["BUSINESS2"])
            if leveltrans(i["level"]) < xiayouLv and (i["_category"] == "父系统") and (i["sysState"] == "已上线"):
                instanceList.append(i["instanceId"])
                tmpDict[i["instanceId"]] = clushBusinfo
    return instanceList, tmpDict


def getInfo(instanceList):
    objectId = "BUSINESS"
    headers = {"user": "easyops", "org": str(EASYOPS_ORG), "content-type": "application/json",
               "host": "cmdb_resource.easyops-only.com"}
    # url = "http://{HOST}/object/{objectId}/instance/_search".format(HOST=EASYOPS_CMDB_HOST.split(":")[0], objectId="BUSINESS")
    if not instanceList:
        print("None list")
        return
    resultDict = []
    for instanceId in instanceList:
        DEPARTMENT1List = []
        systemManagerList = []

        data = {
            "fields": {"name": True, "systemManager.name": True, "DEPARTMENT1.name": True},
            "query": {
                "instanceId": {"$eq": instanceId}
            }
        }
        # res = requests.post(url=url, headers=headers, json=data)
        res = do_requests(url="/cmdb_resource/object/{objectId}/instance/_search".format(objectId=objectId, data=data))
        # print("系统：")
        # print(res.json())
        # print(res.json()["data"]["list"][0]["name"])
        # print("建设负责人：")
        try:
            tList = res.json()["data"]["list"][0]["systemManager"]

            for i in tList:
                systemManagerList.append(i["name"])
            # print(res.json()["data"]["list"])
            # print(systemManagerList)
        except:
            print("no user")
        # print("建设部门")
        try:
            tList = res.json()["data"]["list"][0]["DEPARTMENT1"]
            for i in tList:
                DEPARTMENT1List.append(i["name"])
        except:
            print("no DEPARTMENT")
        # print(DEPARTMENT1List)
        # print(res.json())
        resultDict.append(
            {"BUSINESS NAME": res.json()["data"]["list"][0]["name"], "systemManagerList": systemManagerList,
             "DEPARTMENT1List": DEPARTMENT1List})
    return resultDict


def getUserMail(userNickname):
    # 封装
    orList = []
    if not userNickname:
        print("None list")
        return []
    for i in userNickname:
        orList.append({"nickname": {"$eq": i}})
    QueryData = {
        "fields": {"nickname": 1, "user_email": 1},
        "query": {
            "$or": orList
        },
        "page": 1,
        "page_size": 1000
    }
    res = do_requests(url="/cmdb_resource/object/{objectId}/instance/_search".format(objectId="USER"), data=QueryData)
    # print res.json()["data"]["list"]
    resList = res.json()["data"]["list"]
    emaildict = {}
    for i in resList:
        emaildict.update({i["nickname"]: i["user_email"]})

    # print(emaildict)
    return emaildict


def mailByUser(user_email, content):
    print("send_email to:{0}".format(user_email))
    # 获取用户邮箱

    receivers = [user_email]
    # 收件人
    # receivers.append('jiangzy1@essence.com.cn')  # 收件人邮箱账号
    # receivers.append('yangcy1@essence.com.cn')  # 收件人邮箱账号
    message = json.dumps(content).decode('unicode-escape')
    # 发送邮件
    # print message
    # send_info = mail_info(message)
    send_info = html_mail(message)

    ret = mail_test(send_info, receivers)
    if ret:
        print("邮件发送成功")
    else:
        print("邮件发送失败")


def main():
    objectId = "BUSINESS"
    clushBusinfo = {}
    instanceList = []
    for page in range(1, 1000):
        queryData = {
            "fields": {"instanceId": 1, "name": 1, "number": 1, "sysState": 1, "_category": 1, "level": 1,
                       "systemManager.name": 1, "systemManager.nickname": 1, "BUSINESS1.level": 1, "BUSINESS2.level": 1,
                       "BUSINESS2.name": 1},
            "query": {
            },
            "page_size": 1000,
            "page": page
        }
        # print("page:{}".format(page))
        tmpList, tmpDict = checkInstance(objectId="BUSINESS", queryData=queryData)
        if not tmpList:
            continue
        if tmpList[0] == 'break':
            break
        # time.sleep(1)
        clushBusinfo.update(tmpDict)
        instanceList.extend(tmpList)
    resultList = getInfo(instanceList)
    # ==================================
    # print("异常系统信息：")
    # # print(resultList)
    # print(json.dumps(resultList, indent=2, ensure_ascii=False))
    # ==============================================

    # 邮件发送异常系统信息
    # ======================================================================================================
    # 系统名称|系统编号|系统状态|是否为子系统|是否为重要系统|保障等级|建设负责人工号|建设负责人姓名|部门名称

    # ======================================================================================================
    # 异常系统instanceId
    queryList = []
    for i in instanceList:
        queryList.append({"instanceId": {"$eq": i}})
    QueryData = {
        "fields": {"name": 1, "number": 1, "sysState": 1, "_category": 1, "isImportant": 1, "level": 1,
                   "operationManager.name": 1, "operationManager.nickname": 1, "DEPARTMENT.name": 1,
                   "DEPARTMENT.depName": 1, "BUSINESS2.name": 1, "BUSINESS2.level": 1},
        "query": {
            "$or": queryList
        },
        "page_size": 100,
        "page": 1
    }

    res = do_requests(url="/cmdb_resource/object/{objectId}/instance/_search".format(objectId="BUSINESS"),
                      data=QueryData)

    insInfoList = res.json()["data"]["list"]
    notifyInfo = []

    # 邮件发送异常系统信息
    # ===========================================================================================================================================
    # 系统名称|系统编号|系统状态|是否为子系统|是否为重要系统|保障等级|建设负责人工号|建设负责人姓名|部门|部门名称|下游系统名称|下游系统保障等级

    # ==========================================================================================================================================
    # print "clushBusinfo"
    # print clushBusinfo
    # print("line 511================")
    # print("clushBusinfo:{}".format(json.dumps(clushBusinfo, indent=2, ensure_ascii=False)))
    # ==============================================================================================
    for i in insInfoList:
        # for j in clushBusinfo[i["instanceId"]]:
        for k, v in clushBusinfo[i["instanceId"]][0].items():
            xyName = k
            xyLevel = v
            tmpDict = {}
            tmpDict = {
                "系统名称": i["name"],
                "系统编号": i["number"],
                "系统状态": i["sysState"],
                "是否为子系统": i["_category"],
                "是否为重要系统": i["isImportant"],
                "保障等级": i["level"],
                "运维负责人工号": i["operationManager"][0]["name"],
                "运维负责人姓名": i["operationManager"][0]["nickname"],
                "部门": i["DEPARTMENT"][0]["name"],
                "部门名称": i["DEPARTMENT"][0]["depName"],
                "下游系统": xyName,
                "下游系统的保障等级": xyLevel
            }
            # 补充剩余的不合规下游部门，上面只获取不合规下游部门的一个
            sortList = ["系统名称", "系统编号", "系统状态", "是否为子系统", "是否为重要系统", "保障等级",
                        "运维负责人工号", "运维负责人姓名", "部门", "部门名称", "下游系统", "下游系统的保障等级"]

            # indexNum = 1
            if len(clushBusinfo[i["instanceId"]]) > 1:
                tmpDict = collections.OrderedDict(sorted(tmpDict.items(), key=lambda x: sortList.index(x[0])))
                notifyInfo.append(tmpDict)
                for additem in clushBusinfo[i["instanceId"]][1:]:
                    for k, v in additem.items():
                        # print(indexNum)
                        tmpDict.update({"下游系统": k})
                        tmpDict.update({"下游系统的保障等级": v})
                        # indexNum += 1
            else:
                tmpDict = collections.OrderedDict(sorted(tmpDict.items(), key=lambda x: sortList.index(x[0])))
                notifyInfo.append(tmpDict)
    # userContent报错每个user的信息
    # userNameList报错要通知的用户名
    userContent = {}
    userNameList = []
    # 初始化userContent的value为列表
    for tmp in notifyInfo:
        a = []
        userContent.update({tmp["运维负责人姓名"]: a})
        userNameList.append(tmp["运维负责人姓名"])
    # 将问题系统信息添加到字典的相应负责人中
    for tmp in notifyInfo:
        tmpName = tmp["运维负责人姓名"]
        tmpValue = userContent[tmpName].append(tmp)

    userMaildict = getUserMail(userNameList)
    userNameList = list(set(userNameList))

    print("======================个人邮件通知====================")
    print(json.dumps(userContent, indent=2, ensure_ascii=False))
    print("======================个人邮件通知====================")

    # print "===============系统相关信息================="
    # print json.dumps(notifyInfo, indent=2, ensure_ascii=False)
    # print "===============系统相关信息================="
    # # 给江老板发一个总表
    # mailByUser("jiangzy1@essence.com.cn", notifyInfo)
    # # 给相关负责人发送信息
    # exit()
    for i in userNameList:
        tmpMail = userMaildict[i]
        tmpContent = userContent[i]
        print("user:{0}\n content:{1}\n\n".format(json.dumps(tmpMail, indent=2, ensure_ascii=False),
                                                  json.dumps(tmpContent, indent=2, ensure_ascii=False)))
        mailByUser(tmpMail, tmpContent)

    # 导出excel
    # # 封装query
    # queryList = []
    # for i in instanceList:
    #     queryList.append({"instanceId": {"$eq":i}})

    # print queryList
    # excelQueryData = {
    #     "fields": {"name": 1, "number": 1, "sysState": 1, "_category": 1,  "level": 1, "systemManager.name": 1, "systemManager.nickname": 1, "DEPARTMENT1.name": 1,"DEPARTMENT1.depName":1, "isImportant": 1},
    #     "query": {
    #         "$or": queryList
    #     }
    # }

    # importExcel(objectId="BUSINESS", queryData=excelQueryData)
    # #将excel发送给江正煜
    # mailWithFile("/tmp/shujv.xlsx")


if __name__ == "__main__":
    main()