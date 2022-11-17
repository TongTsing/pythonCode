#!/usr/bin/python
# -*- coding: UTF-8 -*-
import subprocess
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import Header
subprocess.
sender = '17355718009@163.com'
password = "CWMLHIDVIUDWKMEN"
receivers = ['dearhaly@163.com']  # 接收邮件，可设置为你的QQ邮箱或者其他邮箱

# 创建一个带附件的实例
message = MIMEMultipart()
message['From'] = Header("CMDB", 'utf-8')
message['To'] = Header("系统保障等级不规范通知", 'utf-8')
subject = '系统保障等级不规范通知'
message['Subject'] = Header(subject, 'utf-8')

# 邮件正文内容
message.attach(MIMEText('这是一个系统保障等级不规范通知', 'plain', 'utf-8'))

# 构造附件1，传送当前目录下的 test.txt 文件
att1 = MIMEText(open('./test.txt', 'rb').read(), 'base64', 'utf-8')
att1["Content-Type"] = 'application/octet-stream'
# 这里的filename可以任意写，写什么名字，邮件中显示什么名字
att1["Content-Disposition"] = 'attachment; filename="test.txt"'
message.attach(att1)

try:
    smtpObj = smtplib.SMTP_SSL("smtp.163.com")
    smtpObj.login(sender, password)
    smtpObj.sendmail(sender, receivers, message.as_string())
    print("邮件发送成功")
except smtplib.SMTPException:
    print("Error: 无法发送邮件")