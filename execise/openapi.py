# from urllib.request import urlopen
import urllib.error
import urllib3
import fake_user_agent
headers = {
    "user_agent": 'Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.93 Safari/537.36'
}
url = "http://www.baidu.com"
tag =0
try:
    myURL = urllib.request.urlopen(url=url)
    with open('1.txt', 'w+') as f:
        f.write(str(myURL.getcode()))
except urllib.error.HTTPError as e:
    if e.getcode() == 200:
        print(200)


print(myURL.getcode())
# for line in lines_:
#     tag += 1
#     if (tag > 10):
#         break
#     print(line)