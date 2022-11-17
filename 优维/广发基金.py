# -*-coding:utf-8-*-

import sys

reload(sys)
sys.setdefaultencoding('utf8')
import pymysql
import json

host = '10.88.102.52'
port = 3306
db = 'zabbix'
user = 'zabbix'
password = 'GFDW123qwe'


# ---- 用pymysql 操作数据库
def get_connection():
    conn = pymysql.connect(host=host, port=port, db=db, user=user, password=password, use_unicode=True, charset='utf8')
    return conn


def process():
    conn = get_connection()

    # 使用 cursor() 方法创建一个 dict 格式的游标对象 cursor
    cursor = conn.cursor(pymysql.cursors.DictCursor)
    sql_str = "select from_unixtime(clock, '%Y%m%d'),sendto,subject,message from alerts where sendto = 'chenzz' and subject like '%PROBLEM%' and message like '%real_time_failed_task%' and from_unixtime(clock, '%Y%m%d%H%i%S') > date_format(now() - INTERVAL 12 HOUR,'%Y%m%d%H%i%S')"
    # 使用 execute()  方法执行 SQL 查询
    cursor.execute(sql_str)

    # 使用 fetchone() 方法获取单条数据.
    data = cursor.fetchall()

    # print(data)
    # print(len(data))

    # 关闭数据库连接
    cursor.close()
    conn.close()

    res_dic_list = []

    tmp_res_output = {
        'dims': {"data_name": "dcg_etl_failed_task"},
        'vals': {}
    }

    for item in data:
        # print(item)
        # print('\n')
        tmp_msg = item['message'].split('\n')[0]
        tmp_msg_list = tmp_msg.split(',')
        tmp_msg_list_1 = tmp_msg_list[0].split(':')[-1]
        tmp_msg_list_2 = tmp_msg_list[1:]

        # print(tmp_msg_list_1)
        # print(tmp_msg_list_2)
        # print('\n')

        tmp_res_output_1 = {
            'dims': {"data_name": "dcg_etl_failed_taskname"},
            'vals': {}
        }

        tmp_res_output_1['dims']['task_name'] = tmp_msg_list_1
        tmp_res_output_1['vals']['task_name'] = tmp_msg_list_1

        res_dic_list.append(tmp_res_output_1)

        for msg in tmp_msg_list_2:
            tmp_res_output = {
                'dims': {"data_name": "dcg_etl_failed_taskname"},
                'vals': {}
            }

            tmp_res_output['dims']['task_name'] = msg
            tmp_res_output['vals']['task_name'] = msg

            res_dic_list.append(tmp_res_output)

    # print(res_dic_list)
    # print(len(res_dic_list))
    # print('\n')
    print(json.dumps(res_dic_list, ensure_ascii=False).decode('utf8'))


# print(json.dumps(res_dic_list, ensure_ascii=False).decode('gbk'))

if __name__ == '__main__':
    process()