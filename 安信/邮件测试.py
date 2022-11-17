#!/usr/bin/python
# -*- coding: UTF-8 -*-

import smtplib
from email.mime.text import MIMEText
from email.utils import formataddr

my_sender = '17355718009@163.com'  # 发件人邮箱账号
my_pass = 'CWMLHIDVIUDWKMEN'  # 发件人邮箱密码
my_user = 'dearhaly@163.com'  # 收件人邮箱账号，我这边发送给自己


def mail():
    ret = True
    try:
        msg = MIMEText('填写邮件内容', 'plain', 'utf-8')
        msg['From'] = formataddr(["17355718009@163.com", my_sender])  # 括号里的对应发件人邮箱昵称、发件人邮箱账号
        msg['To'] = formataddr(["FK", my_user])  # 括号里的对应收件人邮箱昵称、收件人邮箱账号
        msg['Subject'] = "菜鸟教程发送邮件测试"  # 邮件的主题，也可以说是标题
        print('11111111111')
        server = smtplib.SMTP()
        server.connect("smtp.163.com")
        # server = smtplib.SMTP_SSL("smtp.163.com", 465)  # 发件人邮箱中的SMTP服务器，端口是25
        print("22222222222")
        server.login(my_sender, my_pass)  # 括号中对应的是发件人邮箱账号、邮箱密码
        print("33333333333")
        server.sendmail(my_sender, [my_user, ], msg.as_string())  # 括号中对应的是发件人邮箱账号、收件人邮箱账号、发送邮件
        server.quit()  # 关闭连接
    except Exception:  # 如果 try 中的语句没有执行，则会执行下面的 ret=False
        ret = False
    return ret


ret = mail()
if ret:
    print("邮件发送成功")
else:
    print("邮件发送失败")