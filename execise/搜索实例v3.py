import json
import requests

SERVER_IP = '192.168.110.24'


def get_cluster_host_info(cluter_id):
    # 获取集群主机信息
    """
    :param cluter_id 集群实例id
    :return:
    """
    headers = {
        "host": "cmdb_resource.easyops-only.com",
        "user": "easyops",
        "org": "2041784",
        "content-type":"application/json"
    }

    params = {"query": {"_deviceList_CLUSTER.instanceId": {"$eq": cluter_id}},
              "fields": {"instanceId": True, "ip": True}, "only_relation_view": True, "only_my_instance": False}
    update_user_url = "http://" + SERVER_IP + "/object/" + "HOST" + "/instance/" + "_search"
    response = requests.post(update_user_url, headers=headers, json=params)
    return json.loads(response.content)
    # return response


cluster_id = "5e63e41b7ee87"
cluster = get_cluster_host_info(cluster_id)
# print(cluster)
print(cluster["data"]["list"])