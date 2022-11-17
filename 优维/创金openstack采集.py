#!/usr/local/easyops/python/bin/python
# -*- coding: utf-8 -*-
import json
import urllib2
import requests
import openstack
import yaml
import sys
import os
import re
import threading
import datetime
from hashlib import sha1
import ssl

reload(sys)
sys.setdefaultencoding("utf-8")
ssl._create_unverified_context

# 剔除 InsecureRequestWarning: Unverified HTTPS request is being made to host 'public.fuel.local'
# from requests.packages.urllib3.exceptions import InsecureRequestWarning
# requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import urllib3

urllib3.disable_warnings()

# openstack.enable_logging(debug=True, path='openstack.log', stream=sys.stdout)

# 获取yaml文件路径
# yamlPath = os.path.join("/root/.config/openstack/clouds.yaml")
# open方法打开直接读出来
# f = open(yamlPath, 'r')
# cfg = f.read()
# config_info = yaml.load(cfg,Loader=yaml.FullLoader)

env_name = u"openstack生产环境"
# 　project = 'Industry_dev_cloud_v3'
auth_url = "https://198.19.64.3:5000"
openstack_host = re.findall(r'https://(.*):5000', auth_url)[0]
openstack_username = "huyunyao"
openstack_password = "Crbchyy123!"

headers = {
    "host": "cmdb_resource.easyops-only.com",
    "user": "easyops",
    "org": str(EASYOPS_ORG),
    "content-type": "application/json"
}

# CMDB_IP = '192.168.238.73'
CMDB_IP = EASYOPS_LOCAL_IP

date_now_info = datetime.datetime.now().strftime('%Y-%m-%d')


def cmdb_instance_search(objectId, params):
    url = 'http://{0}/object/{1}/instance/_search'.format(CMDB_IP, objectId)
    result_list = []
    page = 1
    page_size = 200
    count = 0
    while (count >= 0):
        count = 0
        params['page'] = page
        params['page_size'] = page_size
        result = requests.post(url=url, headers=headers, data=json.dumps(params)).json()
        result_list += result['data']['list']
        count = len(result['data']['list']) - page_size
        page += 1
    return result_list


def cmdb_instance_update(objectId, instanceId, params):
    url = 'http://{0}/v2/object/{1}/instance/{2}'.format(CMDB_IP, objectId, instanceId)
    result = requests.put(url=url, headers=headers, data=json.dumps(params)).json()
    return result


def cmdb_instance_create(objectId, params):
    url = 'http://{0}/v2/object/{1}/instance'.format(CMDB_IP, objectId)
    result = requests.post(url=url, headers=headers, data=json.dumps(params)).json()
    return result


class CMDB_API(object):

    def __init__(self, EASYOPS_CMDB_HOST, EASYOPS_ORG, EASYOPS_USER):
        self.EASYOPS_CMDB_HOST = EASYOPS_CMDB_HOST
        self.EASYOPS_ORG = EASYOPS_ORG
        self.EASYOPS_USER = EASYOPS_USER

    # send http query
    def do_http(self, method, url, data={}, files={}, headers={}):
        try:
            method = method.lower()
            if method in ["get", "delete"]:
                resp = requests.request(method, url, params=data, headers=headers, timeout=(1, 60))
            else:
                if files:
                    resp = requests.request(methoe, url, data=data, files=files, headers=headers, timeout=(2, 60))
                else:
                    headers["content-type"] = 'application/json'
                    resp = requests.request(method, url, data=json.dumps(data), headers=headers, timeout=(2, 60))
            return True, resp
        except Exception, e:
            print
            traceback.format_exc()
            return False, None

    # common EasyOps http request method
    def http_request(self, url, method='GET', headers=None, **kwargs):
        # examine the url
        if not (url.startswith('http://') or url.startswith('https://')):
            logger.error(u'url: {url}'.format(url=url))
            raise Exception(u'the url should be start with \'http(s)://\'')

        logger.debug(u'request the url: {url}'.format(url=url))

        # examine the http method
        method = str.upper(method)
        http_methods = ['GET', 'OPTIONS', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE']
        if method not in http_methods:
            raise Exception(u'unsupported http method: {method}'.format(method=method))

        # examine the headers
        if not headers:
            headers = dict()
        if 'org' not in headers:
            headers['org'] = self.EASYOPS_ORG
        if 'user' not in headers:
            headers['user'] = self.EASYOPS_USER

        # execute the request
        '''
        print url
        print method
        print headers
        print params
        '''
        print
        params

        http_ret = requests.request(url=url, method=method, headers=headers, **kwargs)
        if http_ret.status_code == 200:
            try:
                ret_obj = http_ret.json()
                if ret_obj['code'] == 0:
                    return ret_obj['data']
                else:
                    logger.error(http_ret.text)
                    raise Exception(u'Return Code: {code}'.format(code=ret_obj['code']))
            except ValueError:
                return http_ret.content
        else:
            logger.error(http_ret.text)
            raise Exception(u"the http response status code: "
                            u"{status_code}".format(status_code=http_ret.status_code))

    # the http request for EasyOps CMDB
    def send_cmdb_query(self, uri, method='GET', headers=None, params=None, paging=False, **kwargs):
        # construct the url
        url = u"http://{ip}{uri}".format(ip=self.EASYOPS_CMDB_HOST, uri=uri)

        # construct the headers
        if not headers:
            headers = dict()
        headers['Host'] = 'cmdb.easyops-only.com'

        # construct the params
        if params is None:
            params = {'page': 1, 'pageSize': 3000}
        else:
            if not isinstance(params, dict):
                message = u'the type of params should be dictionary, ' \
                          u'but receive: {params}'.format(params=params)
                raise Exception(message)

            if 'page' not in params:
                params['page'] = 1

            if 'pageSize' not in params:
                params['pageSize'] = 3000

        # execute the request
        ret_data = {}
        if paging:
            # with paging, all the result can be receive
            ret_list = []
            while True:
                ret_data = http_request(url=url, method=method, headers=headers, params=params, **kwargs)
                ret_total = ret_data['total']
                ret_list += ret_data['list']

                # when the size of current page is less than pageSize, that will be the last page, break
                if len(ret_data['list']) < params['pageSize']:
                    logger.debug(u"all the data has been received, the request is finished")
                    break

                # when the size of current data is larger than (or equal) res_total, break
                if len(ret_list) < ret_total:
                    params['page'] += 1
                else:
                    logger.debug(u"all the data has been received, the request is finished")
                    break

            # when the all the requests are finished, bring the result to ret_data
            ret_data['list'] = ret_list
        else:
            ret_data = http_request(url=url, method=method, headers=headers, params=params, **kwargs)

        return ret_data

    # cmdb search api
    # ###搜索实例接口(新)
    # POST /object/@object_id/instance/_search
    # 参数说明：
    # object_id -> CMDB资源模型ID              string    必填
    # query     -> 查询条件(写法为mongo查询写法) array
    # page -> 获取的页码数，默认1               int
    # page_size -> 获取每页的数量，默认30        int
    # fields -> 过滤字段, 留空代表返回所有字段    array
    # sort -> 按字段排序, 留空代表不排序
    def cmdb_search(self, objectId, params, paging=False):
        uri = u'/object/{objectId}/instance/_search'.format(objectId=objectId)
        return send_cmdb_query(uri, paging=paging, method='POST', json=params)

    # cmdb add api
    # ###创建实例接口
    # POST /object/@object_id/instance
    # 参数说明：
    # object_id -> CMDB资源模型ID    string    必填
    # name -> 新增的实例名称          string    必填
    def cmdb_add(self, objectId, params):
        uri = u'/object/{objectId}/instance'.format(objectId=objectId)
        return send_cmdb_query(uri, method='POST', json=params)

    # cmdb modity api
    # ###修改实例接口
    # PUT /object/@object_id/instance/@instanceId
    # 参数说明：
    # object_id -> CMDB资源模型ID    string    必填
    # instanceId -> 实例ID          string    必填
    # name -> 新增的实例名称          string    必填
    def cmdb_modity(self, objectId, instanceId, params):
        uri = u'/object/{objectId}/instance/{instanceId}'.format(objectId=objectId, instanceId=instanceId)
        return send_cmdb_query(uri=uri, method='PUT', json=params)

    # cmdb delete api
    # ###删除实例接口
    # DELETE /object/@object_id/instance/@instanceId
    # 参数说明：
    # object_id -> CMDB资源模型ID    string    必填
    # instanceId -> 实例ID          string    必填
    def cmdb_del(self, objectId, instanceId):
        uri = u'/object/{objectId}/instance/{instanceId}'.format(objectId=objectId, instanceId=instanceId)
        return send_cmdb_query(uri=uri, method='DELETE')


CMDB = CMDB_API(EASYOPS_CMDB_HOST, EASYOPS_ORG, EASYOPS_USER)
# 直接使用cmdb接口
use_interface = False


class AutoDiscovery():
    # 定义全局变量autodiscovery_data_list
    global autodiscovery_data_list
    autodiscovery_data_list = []

    # 数据格式化
    def data_format(self, json_data, object_id, pks, upsert=False):
        # json_data：需要上报的数据
        # object_id：CMDB模型ID
        # pks：更新依据，格式为list，例如['name']
        # upsert：不存在实例时是否创建,bool类型，True or False，默认为False
        date_now = datetime.datetime.now().strftime('%Y-%m-%d')
        for data in json_data:
            data['collectDate'] = date_now
            result = {
                'dims': {
                    "pks": pks,  # 用于查询出唯一实例的模型字段组合
                    "object_id": object_id,  # CMDB模型ID
                    "upsert": upsert  # 不存在时是否创建，默认为False
                },
                'vals': data  # 上报的数据
            }
            # 将格式化后的数据append至全局变量autodiscovery_data_list
            autodiscovery_data_list.append(result)

    # 数据上报
    def report_data(self):
        print
        '-----BEGIN GATHERING DATA-----'
        print
        json.dumps(autodiscovery_data_list)
        print
        '-----END GATHERING DATA-----'

    def update_ins_to_cmdb(self, data_list, object_id, pks_attr):
        print
        'update : ', object_id, ' pks:', pks_attr
        update_success = 0
        update_failed = 0
        create_success = 0
        create_failed = 0
        pks_none = 0
        for data in data_list:
            if data.has_key(pks_attr):
                search_params = {
                    "query": {
                        pks_attr: data[pks_attr]
                    }
                }
                ins_res = cmdb_instance_search(object_id, search_params)
                if len(ins_res) != 0:
                    instanceId = ins_res[0]['instanceId']
                    params = data
                    update_res = cmdb_instance_update(object_id, instanceId, params)
                    if update_res['code'] == 0:
                        update_success += 1
                    else:
                        update_failed += 1
                else:
                    params = data
                    create_res = cmdb_instance_create(object_id, params)
                    if create_res['code'] == 0:
                        create_success += 1
                    else:
                        create_failed += 1
            else:
                pks_none += 1
        print
        'update success:', update_success
        print
        'update failed:', update_failed
        print
        'create success:', create_success
        print
        'create failed:', create_failed
        print
        'pks none:', pks_none


AutoDiscovery = AutoDiscovery()


class Openstack_Data():
    def get_content_for_config(self, tenant):
        return openstack.connect(cloud=tenant)

    def get_content(self, auth_url, username, password, project_name):
        return openstack.connect(
            region_name="RegionOne",
            auth=dict(
                auth_url=auth_url,
                username=username,
                password=password,
                project_name=project_name,
                domain_name="default"
            ),
            verify=False

        )

    # 获取节点列表(宿主机列表)(裸机列表) -- 需要openstack开启baremetal服务
    def list_hypervisors(self, conn):
        hypervisor_list = []
        for node in conn.compute.hypervisors(details=True):
            hypervisor_list.append(node.to_dict())
        return hypervisor_list

    # 获取实例列表
    def list_servers(self, conn):
        server_list = []
        for server in conn.compute.servers():
            server_list.append(server.to_dict())
        return server_list

    # 获取实例列表
    def list_servers_all_project(self, conn):
        server_list = []
        for server in conn.compute.servers(all_projects=True):
            server_list.append(server.to_dict())
        return server_list

    # 获取实例类型列表
    def list_flavors(self, conn):
        flavor_list = []
        for flavor in conn.compute.flavors():
            flavor_list.append(flavor.to_dict())
        return flavor_list

    # 获取镜像列表
    def list_images(self, conn):
        image_list = []
        for image in conn.compute.images():
            image_list.append(image.to_dict())
        return image_list

    # 获取网络列表
    def list_networks(self, conn):
        network_list = []
        for network in conn.network.networks():
            network_list.append(network.to_dict())
        return network_list

    # 获取子网列表
    def list_subnets(self, conn):
        subnet_list = []
        for subnet in conn.network.subnets():
            subnet_list.append(subnet.to_dict())
        return subnet_list

    # 获取端口列表
    def list_ports(self, conn):
        port_list = []
        for port in conn.network.ports():
            port_list.append(port.to_dict())
        return port_list

    # 获取安全组列表
    def list_security_groups(self, conn):
        security_group_list = []
        for security_group in conn.network.security_groups():
            security_group_list.append(security_group.to_dict())
        return security_group_list

    # 获取路由器列表
    def list_routers(self, conn):
        routers_list = []
        for router in conn.network.routers():
            routers_list.append(router.to_dict())
        return routers_list

    # 获取网络代理列表
    def list_network_agents(self, conn):
        network_agent_list = []
        for network_agent in conn.network.agents():
            network_agent_list.append(network_agent.to_dict())
        return network_agent_list

    # 获取区域列表 -- 需要openstack开启dns服务
    def list_zones(self, conn):
        zone_list = []
        for zone in conn.dns.zones():
            zone_list.append(zone.to_dict())
        return zone_list

    # 获取用户列表
    def list_users(self, conn):
        user_list = []
        for user in conn.identity.users():
            user_list.append(user.to_dict())
        return user_list

    # 获取项目(租户)列表
    def list_tenant(self, conn):
        tenant_list = []
        for tenant in conn.identity.projects():
            tenant_list.append(tenant.to_dict())
        return tenant_list

    def list_volumes(self, conn):
        volumes_list = []
        for volumes in conn.block_storage.volumes():
            volumes_list.append(volumes.to_dict())
        return volumes_list

    def list_volumes_all_project(self, conn):
        volumes_list = []
        for volumes in conn.block_storage.volumes(all_projects=True):
            volumes_list.append(volumes.to_dict())
        return volumes_list


class Openstack_Process():
    # 处理云硬盘信息
    def process_volumes(self, volumes_list):
        filter_list = []
        for volumes in volumes_list:
            filter_list.append({
                'name': encrypt(str(volumes.get('id')) + env_name),
                "device_name": str(volumes.get("name")),
                "migration_status": str(volumes.get("migration_status")),
                # "links":str(volumes.get("links")),
                "availability_zone": str(volumes.get("availability_zone")),
                "source_volume_id": str(volumes.get("source_volume_id")),
                "replication_status": str(volumes.get("replication_status")),
                "snapshot_id": str(volumes.get("snapshot_id")),
                "id": str(volumes.get("id")),
                "size": str(volumes.get("size")),
                "location": str(volumes.get("location")),
                "project_id": str(volumes.get("project_id")),
                "status": str(volumes.get("status")),
                "description": str(volumes.get("description")),
                "is_bootable": str(volumes.get("is_bootable")),
                "host": str(volumes.get("host")),
                "collectDate": date_now_info,
                "created_at": str(volumes.get("created_at")),
                "is_encrypted": str(volumes.get("is_encrypted")),
                "volume_type": str(volumes.get("volume_type")),
                "migration_id": str(volumes.get("migration_id")),
                "replication_driver_data": str(volumes.get("replication_driver_data")),
                "extended_replication_status": str(volumes.get("extended_replication_status")),
                'OPENSTACK_ADMIN': [{'name': env_name}],
                'OPENSTACK_TENANT': [{'name': volumes.get('project_id')}] if volumes.get('project_id') else []
            })
        return filter_list

    # 处理租户列表信息
    def process_tenant(self, tenant_list):
        filter_list = []
        # 处理openstack接口获取的数据，生成CMDB可以写入的字段数据
        for tenant in tenant_list:
            filter_list.append({
                'tenantName': str(tenant.get('name')),
                'name': str(tenant.get('id')),
                'enable': str(tenant.get('is_enabled')),
                'description': str(tenant.get('description')),
                "collectDate": date_now_info,
                "TENANT": [{"tenantName": str(tenant.get('name')).strip()}],
                'OPENSTACK_ADMIN': [{'name': env_name}]
            })
        return filter_list

    # 处理镜像列表
    def process_image(self, image_list):
        filter_list = []
        # 处理openstack接口获取的数据，生成CMDB可以写入的字段数据
        for image in image_list:
            filter_list.append({
                'name': encrypt(image.get('id') + env_name),
                'image_name': str(image.get('name')),
                'id': str(image.get('id')),
                # 'overallID': encrypt(image.get('id') + env_name),
                'status': str(image.get('status')),
                'size': int(image.get('size')) / 1024 / 1024,
                "collectDate": date_now_info,
                # 'diskFormat': '',
                # 'description': '',
                'minRAM': int(image.get('min_ram')),
                'OPENSTACK_ADMIN': [{'name': env_name}],
            })
        return filter_list

    # 处理实例类型列表
    def process_flavor(self, flavor_list):
        filter_list = []
        # 处理openstack接口获取的数据，生成CMDB可以写入的字段数据
        for flavor in flavor_list:
            filter_list.append({
                'name': encrypt(flavor.get('id') + env_name),
                'flavor_name': str(flavor.get('name')),
                'id': str(flavor.get('id')),
                # 'overallID': encrypt(flavor.get('id') + env_name),
                'ram': str(flavor.get('ram')),
                'isPublic': str(flavor.get('is_public')).capitalize(),
                'vcpus': str(flavor.get('vcpus')),
                'disk': str(flavor.get('disk')),
                "collectDate": date_now_info,
                'rxtxFactor': str(flavor.get('rxtx_factor')),
                'swap': str(flavor.get('swap')),
                'ephemeral': str(flavor.get('ephemeral')),
                'OPENSTACK_ADMIN': [{'name': env_name}],
            })
        return filter_list

    # 处理网络列表
    def process_network(self, network_list):
        filter_list = []
        # 处理openstack接口获取的数据，生成CMDB可以写入的字段数据
        for network in network_list:
            filter_list.append({
                'name': encrypt(network.get('id') + env_name),
                'network_name': str(network.get('name')),
                'id': str(network.get('id')),
                # 'overallID': encrypt(network.get('id') + env_name),
                'networkType': str(network.get('provider_network_type')).lower().capitalize(),
                'createdAt': network.get('created_at'),
                'updatedAt': network.get('updated_at'),
                'status': str(network.get('status')),
                'external': str(network.get('is_router_external')).capitalize(),
                "collectDate": date_now_info,
                'shared': str(network.get('is_shared')).capitalize(),
                'tenantId': str(network.get('project_id')),
                'mtu': int(network.get('mtu')) if network.get('mtu') else None,
                'adminStatus': 'UP' if network.get('is_admin_state_up') else 'DOWN',
                'providerSegmentationID': str(network.get('provider_segmentation_id')),
                # 'tenant': [{'tenantID': network.get('project_id')}],
                'OPENSTACK_ADMIN': [{'name': env_name}],
            })
        return filter_list

    # 处理端口列表
    def process_port(self, port_list):
        filter_list = []
        # 处理openstack接口获取的数据，生成CMDB可以写入的字段数据
        for port in port_list:
            filter_list.append({
                'name': encrypt(port.get('id') + env_name),
                'id': str(port.get('id')),
                'portName': str(port.get('name')),
                'fixedIps': [i.get('ip_address') for i in port.get('fixed_ips')],
                'mac': str(port.get('mac_address')),
                'status': port.get('status'),
                "collectDate": date_now_info,
                'adminStatus': 'UP' if port.get('is_admin_state_up') else 'DOWN',
                'isPortSecurityEnabled': str(port.get('is_port_security_enabled')).capitalize(),
                'deviceInfo': [{'deviceOwner': port.get('device_owner'), 'deviceID': port.get('device_id')}],
                'binding': [
                    {
                        'bindingVnicType': port.get('binding_vnic_type'),
                        'hostname': port.get('binding_host_id'),
                        'bindingVifType': port.get('binding_vif_type'),
                        'bindingVifDetails': str(port.get('binding_vif_details')),
                    }
                ],
                # 'overallID': encrypt(port.get('id') + env_name),
                'OPENSTACK_NETWORK': [{'id': port.get('network_id')}] if port.get('network_id') else [],
                'OPENSTACK_ADMIN': [{'name': env_name}],
                'OPENSTACK_TENANT': [{'name': port.get('project_id')}] if port.get('project_id') else [],
                'OPENSTACK_SERVERS': [{'id': port.get('device_id')}] if port.get('device_id') else []
            })
        return filter_list

    # 处理子网列表
    def process_subnet(self, subnet_list):
        filter_list = []
        # 处理openstack接口获取的数据，生成CMDB可以写入的字段数据
        for subnet in subnet_list:
            filter_list.append({
                'name': encrypt(subnet.get('id') + env_name),
                'subnet_name': str(subnet.get('name')),
                'id': str(subnet.get('id')),
                # 'overallID': encrypt(subnet.get('id') + env_name),
                'ipVersion': 'IPv' + str(subnet.get('ip_version')),
                'cidr': subnet.get('cidr'),
                "collectDate": date_now_info,
                'allocationPools': [
                    {
                        'start': i.get('start'),
                        'end': i.get('end'),
                    } for i in subnet.get('allocation_pools')
                ],
                'gatewayIP': subnet.get('gateway_ip'),
                'isDhcpEnable': str(subnet.get('is_dhcp_enabled')).capitalize(),
                'createdAt': subnet.get('created_at'),
                'updatedAt': subnet.get('updated_at'),
                'OPENSTACK_NETWORK': [{'id': subnet.get('network_id')}] if subnet.get('network_id') else [],
                'OPENSTACK_ADMIN': [{'name': env_name}],
                'OPENSTACK_TENANT': [{'name': subnet.get('project_id')}] if subnet.get('project_id') else []
            })
        return filter_list

    def process_router(self, router_list):
        filter_list = []
        # 处理openstack接口获取的数据，生成CMDB可以写入的字段数据
        for router in router_list:
            filter_list.append({
                'name': encrypt(router.get('id') + env_name),
                'router_name': str(router.get('name')),
                'id': str(router.get('id')),
                # 'overallID': encrypt(router.get('id') + env_name),
                'zone': str(router.get('availability_zones')),
                "collectDate": date_now_info,
                'status': str(router.get('status')),
                'isDistributed': str(router.get('is_distributed')).capitalize(),
                'adminStatus': 'UP' if router.get('is_admin_state_up') else 'DOWN',
                'OPENSTACK_TENANT': [{'name': str(router.get('project_id'))}] if router.get('project_id') else [],
                'OPENSTACK_ADMIN': [{'name': str(env_name)}],
            })
        return filter_list

    # 处理节点列表
    def process_hypervisor(self, hypervisor_list):
        filter_list = []
        # 处理openstack接口获取的数据，生成CMDB可以写入的字段数据
        for hypervisor in hypervisor_list:
            if hypervisor.get('name'):
                hypervisor_name = str(hypervisor.get('name'))
            else:
                hypervisor_name = str(hypervisor.get('hypervisor_hostname'))
            if hypervisor.get('local_disk_size'):
                localGB = str(hypervisor.get('local_disk_size'))
            else:
                localGB = str(hypervisor.get('local_gb'))
            if hypervisor.get('memory_size'):
                memoryMB = str(hypervisor.get('memory_size'))
            else:
                memoryMB = str(hypervisor.get('memory_mb'))
            if hypervisor.get('memory_used'):
                memoryMBUsed = str(hypervisor.get('memory_used'))
            else:
                memoryMBUsed = str(hypervisor.get('memory_mb_used'))
            if hypervisor.get('local_disk_used'):
                localGBUsed = str(hypervisor.get('local_disk_used'))
            else:
                localGBUsed = str(hypervisor.get('local_gb_used'))
            if hypervisor.get('host_ip'):
                host_ip = str(hypervisor.get('host_ip'))
            if hypervisor.get('status'):
                status = str(hypervisor.get('status'))
            if hypervisor.get('state'):
                state = str(hypervisor.get('state'))

            filter_list.append({
                'name': encrypt(str(hypervisor.get('id')) + env_name),
                'hypervisor_name': hypervisor_name,
                'id': str(hypervisor.get('id')),
                # 'overallID': encrypt(str(hypervisor.get('id')) + env_name),
                'hypervisorType': str(hypervisor.get('hypervisor_type')),
                'vcpus': int(hypervisor.get('vcpus')),
                'vcpusUsed': int(hypervisor.get('vcpus_used')),
                'memoryMB': memoryMB,
                "collectDate": date_now_info,
                'memoryMBUsed': memoryMBUsed,
                'localGB': localGB,
                'localGBUsed': localGBUsed,
                'runningVMs': int(hypervisor.get('running_vms')),
                'OPENSTACK_ADMIN': [{'name': env_name}],
                'ip': str(hypervisor.get('host_ip')) or '',
                'status': str(hypervisor.get('status')) or '',
                'state': str(hypervisor.get('state')) or '',
                "availabilityZone": str(hypervisor.get('availabilityZone') or '')
                # 'openstack_network': {'name': },
            })
        return filter_list

    # 处理实例列表
    def process_server(self, server_list, flavor_list):
        filter_list = []
        # 处理openstack接口获取的数据，生成CMDB可以写入的字段数据
        num = 0
        power_state_dict = {
            "0": u'NOSTATE',
            "1": u'Running',
            "3": u'PAUSED',
            "4": u"SHUTDOWN",
            "6": u"CRASHED",
            "7": u"SUSPENDED",
            "-1": u"未知"
        }
        for server in server_list:
            # print json.dumps(server, indent=2)
            result_dict = {
                'name': encrypt(str(server.get('id')) + env_name),
                'server_name': str(server.get('name')),
                'id': str(server.get('id')),
                'image': str(server.get('image').get('id')).strip(),
                # 'overallID': encrypt(str(server.get('id')) + env_name),
                'availabilityZone': str(server.get('availability_zone')),
                'status': str(server.get('status')),
                'powerStatus': power_state_dict.get(str(server.get('power_state', '-1'))),
                'description': str(server.get('description')),
                "collectDate": date_now_info,
                # 'OPENSTACK_FLAVOR': [{'name': encrypt(server.get('flavor').get('id') + env_name)}] if server.get('flavor') else [] ,
                'OPENSTACK_FLAVOR': [{'id': server.get('flavor').get('id')}] if server.get('flavor') else [],
                'OPENSTACK_TENANT': [{'name': server.get('project_id')}] if server.get('project_id') else [],
                'OPENSTACK_ADMIN': [{'name': env_name}],
                'OPENSTACK_NODE': [{'hypervisor_name': server.get('hypervisor_hostname')}] if server.get(
                    'hypervisor_hostname') else [],
                'node': str(server.get('hypervisor_hostname')) or '',
                # 'OPENSTACK_IMAGE': [{'name': encrypt(server.get('image').get('id') + env_name)}] if server.get('image') else [],
                'OPENSTACK_IMAGE': [{'id': str(server.get('image').get('id')).strip()}] if server.get('image') else [],
                'OPENSTACK_STORAGE': server.get('attached_volumes'),
                # 'openstack_network': {'name': },
                'IP': ' '.join(self.get_server_ip(server)),
                'mac': ' '.join(self.get_server_mac(server)),
                'sname': server.get('instance_name'),
                'createAt': server.get('created_at'),
                'updatedAt': server.get('updated_at'),
                'root_device_name': server.get('root_device_name'),
                'compute_host': server.get('compute_host', ''),  # 宿主机
                'is_locked': True if str(server.get('is_locked')) == 'True' else False,
                'address': [
                    {
                        'net': k,
                        'ip': ' '.join([i.get('addr') for i in v]),
                        'mac': ' '.join([i.get('OS-EXT-IPS-MAC:mac_addr') for i in v]),
                    } for k, v in server.get('addresses').items()
                ],
            }
            '''
            storage_list = []
            if len(server.get('attached_volumes')) > 0:
                for storage in server.get('attached_volumes'):
                    if storage.has_key("id"):
                        storage_list.append({"id":storage["id"]})
            result_dict['OPENSTACK_STORAGE'] = storage_list
            '''
            if server.get('flavor'):
                flavor_id = server.get('flavor').get('id')
                # 遍历image
                for flavor in flavor_list:
                    if flavor['id'] == flavor_id:
                        result_dict['flavor_name'] = flavor.get('flavor_name', '')
                        if flavor.has_key('vcpus'):
                            result_dict['vcpus'] = flavor.get('vcpus', '')
                        if flavor.has_key('ram'):
                            result_dict['memory'] = flavor.get('ram')
                        if flavor.has_key('disk'):
                            result_dict['disk'] = flavor.get('disk')
                        '''
                        if image.has_key('disk'):
                            result_dict['disk']
                        '''
                        break
            print
            json.dumps(result_dict, indent=2)
            # if num == 1:
            #     exit()
            filter_list.append(result_dict)
        return filter_list

    def get_server_ip(self, server):
        addr_list = []
        for i in server.get('addresses').values():
            addr_list.extend(i)
        return [i.get('addr') for i in addr_list]

    def get_server_mac(self, server):
        addr_list = []
        for i in server.get('addresses').values():
            addr_list.extend(i)
        return [i.get('OS-EXT-IPS-MAC:mac_addr') for i in addr_list]


# 加密算法，计算唯一ID
def encrypt(str):
    sh = sha1()
    sh.update(str.encode())
    return sh.hexdigest()


# 解析cloud.yaml配置文件
def paser_config(config_path):
    with open(config_path) as fr:
        config_dict = yaml.load(fr, Loader=yaml.FullLoader)

    tenant_list = config_dict.get('clouds').keys()
    return tenant_list


# 上报前对采集的数据去重，减小平台压力
def duplicated(list):
    list_key = []
    new_list = []
    for i in list:
        # if i.get('overallID') not in list_key:
        if i.get('name') not in list_key:
            new_list.append(i)
            # list_key.append(i.get('overallID'))
            list_key.append(i.get('name'))
    return new_list


def get_userId_for_V2(host):
    url = "https://{0}:5000/v2.0/tokens".format(host)
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    params = {
        "auth": {
            "tenantName": "admin",
            "passwordCredentials": {
                "username": openstack_username,
                "password": openstack_password
            }
        }
    }
    res = requests.post(url=url, headers=headers, data=json.dumps(params), verify=False)
    userId = res.json()['access']['user']['id']
    return userId


def restful_auth():
    userId = get_userId_for_V2(openstack_host)
    # url = "https://172.21.240.3:5000/v2.0/tokens"
    url = "https://{0}:5000/v3/auth/tokens".format(openstack_host)
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    params = {
        "auth": {
            "identity": {
                "methods": [
                    "password"
                ],
                "password": {
                    "user": {
                        "id": userId,
                        "password": openstack_password
                    }
                }
            },
            "scope": {
                "domain": {
                    "id": "default"
                }
            }
        }
    }
    res = requests.post(url=url, headers=headers, data=json.dumps(params), verify=False)
    token = res.headers["X-Subject-Token"]
    return token


def get_projects_for_restful_v3(host, token):
    url = "https://{0}:5000/v3/projects".format(host)
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-Auth-Token": token
    }
    res = requests.get(url=url, headers=headers, verify=False)
    source_tenant_list = res.json()["projects"]
    return source_tenant_list


def get_hypervisors_for_restful_v3(host, token):
    url = "https://{0}:8774/v2.1/os-hypervisors/detail".format(host)
    # 可用域
    url_zone = "https://{0}:8774/v2.1/os-availability-zone/detail".format(host)
    # url = "https://public.nf-region02.sscc.com:8774/v2.1/servers/detail?all_tenants=True"
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-Auth-Token": token
    }
    res = requests.get(url=url, headers=headers, verify=False)
    res_zone = requests.get(url=url_zone, headers=headers, verify=False)
    count = 0
    zone_dict = {}
    source_hypervisor_list = []
    for zone_result in res_zone.json()['availabilityZoneInfo']:
        zoneName = zone_result["zoneName"]
        if zone_result.get("hosts"):
            for hostname_info in zone_result['hosts'].keys():
                zone_dict[hostname_info] = zoneName
    # print zone_dict
    for hypervisors in res.json()['hypervisors']:
        if hypervisors['hypervisor_hostname'] in zone_dict.keys():
            hypervisors["availabilityZone"] = zone_dict[hypervisors['hypervisor_hostname']]
        source_hypervisor_list.append(hypervisors)
    # source_hypervisor_list = res.json()['hypervisors']
    return source_hypervisor_list


def get_servers_for_restful_v3(host, token):
    url = "https://{0}:8774/v2.1/servers".format("public.nf-region02.sscc.com")
    # url = "https://public.nf-region02.sscc.com:8774/v2.1/servers/detail?all_tenants=True"
    headers = {
        "Content-Type": "application/vnd.openstack.compute+json;version=2.1",
        "Accept": "application/json",
        "X-Auth-Token": token
    }
    params = {
        "all_tenants": True
    }
    res = requests.get(url=url, headers=headers, data=json.dumps(params), verify=False)
    print
    res.json()
    # source_servers_list = res.json()['servers']
    # return source_servers_list


Openstack_Data = Openstack_Data()
Openstack_Process = Openstack_Process()


class MyThread(threading.Thread):

    def __init__(self, func, args, name=''):
        threading.Thread.__init__(self)
        self.name = name
        self.func = func
        self.args = args

    def run(self):
        apply(self.func, self.args)


lock = threading.Lock()

openstack_project_info = {}


def openstack_collect(num, project_info):
    # 遍历project采集
    # print num
    for project in project_info:
        openstack_project_info[project["name"]] = {}
        server_list = []
        image_list = []
        network_list = []
        flavor_list = []
        # tenant_list = []
        subnet_list = []
        port_list = []
        router_list = []
        # hypervisor_list = []
        volumes_list = []
        print
        "---collect project name is :", project["name"]
        # conn = Openstack_Data.get_content(project["name"])
        conn = Openstack_Data.get_content(auth_url, openstack_username, openstack_password, project["name"])
        # print "collect image..."
        try:
            source_image_list = Openstack_Data.list_images(conn)
        except Exception, e:
            # print "collect image..."
            # print "    --ERROR: collect failed:",e
            source_image_list = []
        # print "collect flavor..."
        try:
            source_flavor_list = Openstack_Data.list_flavors(conn)
        except Exception, e:
            # print "collect flavor..."
            # print "    --ERROR: collect failed:",e
            source_flavor_list = []
        # print "collect network"
        try:
            source_network_list = Openstack_Data.list_networks(conn)
        except Exception, e:
            # print "collect network..."
            # print "    --ERROR: collect failed:",e
            source_network_list = []
        # print "collect server..."
        try:
            # print "    --collect all project..."
            source_server_list = Openstack_Data.list_servers_all_project(conn)
        except Exception, e:
            # print "collect server..."
            # print "    --ERROR: collect all project failed:",e
            # print "    --change to user project..."
            try:
                source_server_list = Openstack_Data.list_servers(conn)
            except Exception, e:
                source_server_list = []
                # print "      ERROR: collect user project failed",e
        # print "collect subnet..."
        try:
            source_subnet_list = Openstack_Data.list_subnets(conn)
        except Exception, e:
            # print "collect subnet..."
            # print "    --ERROR: collect failed:",e
            source_subnet_list = []
        # print "collect port..."
        try:
            source_port_list = Openstack_Data.list_ports(conn)
        except Exception, e:
            # print "collect port..."
            # print "    --ERROR: collect failed:",e
            source_port_list = []
        # print "collect router..."
        try:
            source_router_list = Openstack_Data.list_routers(conn)
        except Exception, e:
            # print "collect router..."
            # print "    --ERROR: collect failed:",e
            source_router_list = []
        # print "vollect volumes..."
        try:
            # print "    --collect all project..."
            source_volumes_list = Openstack_Data.list_volumes_all_project(conn)
        except Exception, e:
            # print "collect volumes..."
            # print "    --ERROR: collect all project failed:",e
            # print "      --change to user project..."
            try:
                source_volumes_list = Openstack_Data.list_volumes(conn)
            except Exception, e:
                source_volumes_list = []
                # print "      ERROR: collect user project failed",e
        # 已经CMDB定义的字段处理数据，生成CMDB可以直接上报的数据
        volumes_list += Openstack_Process.process_volumes(source_volumes_list)
        image_list += Openstack_Process.process_image(source_image_list)
        flavor_list += Openstack_Process.process_flavor(source_flavor_list)
        network_list += Openstack_Process.process_network(source_network_list)
        server_list += Openstack_Process.process_server(source_server_list, flavor_list)
        subnet_list += Openstack_Process.process_subnet(source_subnet_list)
        port_list += Openstack_Process.process_port(source_port_list)
        router_list += Openstack_Process.process_router(source_router_list)
        openstack_project_info[project["name"]]["volumes_list"] = volumes_list
        openstack_project_info[project["name"]]["image_list"] = image_list
        openstack_project_info[project["name"]]["flavor_list"] = flavor_list
        openstack_project_info[project["name"]]["network_list"] = network_list
        openstack_project_info[project["name"]]["server_list"] = server_list
        openstack_project_info[project["name"]]["subnet_list"] = subnet_list
        openstack_project_info[project["name"]]["port_list"] = port_list
        openstack_project_info[project["name"]]["router_list"] = router_list
    return openstack_project_info


def autodiscovery_api(json_data, object_id, pks, upsert=False):
    headers['host'] = 'cmdb_resource.easyops-only.com'
    # 获取模型定义
    url_obj_info = "http://{0}/object/{1}".format(CMDB_IP, object_id)
    object_res = requests.get(url_obj_info, headers=headers).json()

    # 实例数据上报===================================================================
    url_ins = "http://{0}/object/{1}/instance/_import-json".format(CMDB_IP, object_id)

    params_list = []

    for data in json_data:
        # 实例数据=========================================================
        # 更新依据
        filter_dict = {}
        error_msg = ""
        for pks_info in pks:
            if data.has_key(pks_info):
                filter_dict[pks_info] = data[pks_info]
            else:
                error_msg = "发现更新依据为空，忽略该数据：", data
        if error_msg:
            print
            error_msg
        else:
            # 更新依据不为空的数据，才加入上报列表
            params = {
                "filter": filter_dict,
                "update": data,
                "upsert": upsert
            }
            params_list.append(params)
        # 关系数据=====================================================
    if params_list:
        # print params_list
        res = requests.post(url=url_ins, headers=headers, data=json.dumps(params_list)).json()
        update_success = 0
        update_failed = 0
        for res_info in res["data"]:
            if res_info["code"] == 0:
                update_success += 1
            else:
                update_failed += 1
        print
        object_id, "上报实例总数：", len(params_list)
        print
        "  - update success:", update_success
        print
        "  - update failed:", update_failed
    # 关系数据上报==========================================================================
    # 取出模型所有关系字段
    obj_relation_list = object_res['data']['relation_list']
    relation_dict = {}
    for relation in obj_relation_list:
        # 取出所有关系别名和关系id的关系
        # print relation
        # 判断模型在关系左端，还是在右端
        if relation['right_object_id'] == object_id:
            relation_dict[relation["right_id"]] = {
                "relation_id": relation["relation_id"],
                "relation_type": "right"
            }
        else:
            relation_dict[relation["left_id"]] = {
                "relation_id": relation["relation_id"],
                "relation_type": "left"
            }
    # print relation_dict
    relation_info_dict = {}
    for data in json_data:
        # 遍历实例的key
        for data_key in data.keys():
            # 判断key是否在关系中
            if data_key in relation_dict.keys() and len(data[data_key]) > 0:
                instance_info = {}
                for pks_key in pks:
                    instance_info[pks_key] = data[pks_key]
                data_list_info = []
                if relation_dict[data_key]["relation_type"] == "left":
                    for remote_ins in data[data_key]:
                        data_dict = {
                            "left_instance": instance_info,
                            "right_instance": remote_ins
                        }
                        data_list_info.append(data_dict)
                else:
                    for remote_ins in data[data_key]:
                        data_dict = {
                            "left_instance": remote_ins,
                            "right_instance": instance_info
                        }
                        data_list_info.append(data_dict)
                if data_list_info:
                    if relation_info_dict.has_key(data_key):
                        relation_info_dict[data_key]["data"] += data_list_info
                    else:
                        match_dict = {}
                        relation_pks = data[data_key][0].keys()
                        if relation_dict[data_key]["relation_type"] == "left":
                            match_dict["left_match"] = pks
                            match_dict["right_match"] = relation_pks
                        else:
                            match_dict["left_match"] = relation_pks
                            match_dict["right_match"] = pks
                        relation_info_dict[data_key] = {
                            "match": match_dict,
                            "strict": True,
                            "data": data_list_info
                        }
    if relation_info_dict:
        for relation_key in relation_info_dict.keys():
            # 上报关系
            print
            "  --上报关系: ", relation_key
            print
            "        --关系数据总计:", len(relation_info_dict[relation_key]['data'])
            relation_id = relation_dict[relation_key]["relation_id"]
            url_relation = "http://{0}/object_relation/{1}/_autodiscovery".format(CMDB_IP, relation_id)
            rel_params = relation_info_dict[relation_key]
            relation_res = requests.post(url=url_relation, headers=headers, data=json.dumps(rel_params)).json()
            relation_add_success = 0
            relation_add_failed = 0
            relation_repeat = 0
            relation_none = 0
            if relation_res["data"] == None:
                continue
            for add_relation_info in relation_res["data"]:
                if add_relation_info["code"] == 0:
                    relation_add_success += 1
                elif add_relation_info["code"] == 133132:
                    relation_repeat += 1
                elif add_relation_info["code"] == 133600:
                    relation_none += 1
                else:
                    relation_add_failed += 1
                    # print "关系添加失败：",add_relation_info
            print
            "            - 关系添加成功:", relation_add_success
            print
            "            - 关系添加失败:", relation_add_failed
            print
            "            - 关系已存在:", relation_repeat
            print
            "            - 关系实例不存在:", relation_none
    else:
        print
        "  --无关系数据"
    print
    "=======================update end==============================="


if __name__ == '__main__':
    token = ""
    # env_name = u"行业开发测试云"
    # os.chdir('/root/openstack_auto_detect')
    # Openstack_Data = Openstack_Data()
    # Openstack_Process = Openstack_Process()

    # server_list = Openstack_Process.process_server(source_server_list,flavor_list)
    # print server_list
    # project_list = paser_config('/root/')
    tenant_list = []
    hypervisor_list = []

    # 从openstack接口获取需要采集的资源源信息
    # openstack.enable_logging(debug=True)
    conn = Openstack_Data.get_content(auth_url, openstack_username, openstack_password, "admin")
    # 获取所有节点
    print
    "collect all hypervisor..."
    try:
        source_hypervisor_list = Openstack_Data.list_hypervisors(conn)
    except:
        try:
            if token == "":
                token = restful_auth()
                print
                token
            source_hypervisor_list = get_hypervisors_for_restful_v3(openstack_host, token)
        except Exception, e:
            print
            "    --ERROR: collect failed:", e
            source_hypervisor_list = []
    # 获取所有project
    print
    "collect all tenant..."
    try:
        source_tenant_list = Openstack_Data.list_tenant(conn)
    except:
        try:
            token = restful_auth()
            source_tenant_list = get_projects_for_restful_v3(openstack_host, token)
        except Exception, e:
            print
            "    --ERROR: collect failed:", e
            source_tenant_list = []
    threads = []
    num = 2
    files_page_num = len(source_tenant_list) // num
    if len(source_tenant_list) % num != 0:
        files_page_num += 1
    files = range(files_page_num)
    dict_info = {}
    for j in files:
        start_num = j * num
        end_num = (j + 1) * num
        dict_info[str(j)] = source_tenant_list[start_num:end_num]
    openstack_project_info = openstack_collect("0", dict_info["0"])
    for k, v in dict_info.items():
        t = MyThread(openstack_collect, (k, v), openstack_collect.__name__)
        threads.append(t)
    for i in files:
        threads[i].start()
    for i in files:
        threads[i].join()
    image_id_list = []
    image_list = []
    flavor_id_list = []
    flavor_list = []

    network_id_list = []
    network_list = []

    server_id_list = []
    server_list = []

    subnet_id_list = []
    subnet_list = []

    port_id_list = []
    port_list = []

    router_id_list = []
    router_list = []

    volumes_id_list = []
    volumes_list = []
    for project_name in openstack_project_info.keys():
        for image in openstack_project_info[project_name]["image_list"]:
            if image["id"] not in image_id_list:
                image_list.append(image)
                image_id_list.append(image["id"])

        for flavor in openstack_project_info[project_name]["flavor_list"]:
            if flavor["id"] not in flavor_id_list:
                flavor_list.append(flavor)
                flavor_id_list.append(flavor["id"])

        for network in openstack_project_info[project_name]["network_list"]:
            if network["id"] not in network_id_list:
                network_list.append(network)
                network_id_list.append(network["id"])
        for server in openstack_project_info[project_name]["server_list"]:
            # print json.dumps(server, indent=2)
            if server["id"] not in server_id_list:
                if server.has_key("node") and server["node"] != "None":
                    server_list.append(server)
                    server_id_list.append(server["id"])
                else:
                    msg = server["id"], " node is null"

        for subnet in openstack_project_info[project_name]["subnet_list"]:
            if subnet["id"] not in subnet_id_list:
                subnet_list.append(subnet)
                subnet_id_list.append(subnet["id"])

        for port in openstack_project_info[project_name]["port_list"]:
            if port["id"] not in port_id_list:
                port_list.append(port)
                port_id_list.append(port["id"])

        for router in openstack_project_info[project_name]["router_list"]:
            if router["id"] not in router_id_list:
                router_list.append(router)
                router_id_list.append(router["id"])

        for volumes in openstack_project_info[project_name]["volumes_list"]:
            if volumes["id"] not in volumes_id_list:
                volumes_list.append(volumes)
                volumes_id_list.append(volumes["id"])
    # for project in source_tenant_list:
    # print json.dumps(source_hypervisor_list)
    tenant_list += Openstack_Process.process_tenant(source_tenant_list)
    hypervisor_list += Openstack_Process.process_hypervisor(source_hypervisor_list)
    # 上报数据到CMDB
    autodiscovery_api(json_data=tenant_list, object_id='OPENSTACK_TENANT', pks=['name'], upsert=True)
    # 镜像
    autodiscovery_api(json_data=image_list, object_id='OPENSTACK_IMAGE', pks=['name'], upsert=True)
    # 实例类别
    autodiscovery_api(json_data=flavor_list, object_id='OPENSTACK_FLAVOR', pks=['name'], upsert=True)
    # 节点
    autodiscovery_api(json_data=duplicated(hypervisor_list), object_id='OPENSTACK_NODE', pks=['name'], upsert=True)
    # 网络
    autodiscovery_api(json_data=network_list, object_id='OPENSTACK_NETWORK', pks=['name'], upsert=True)
    # 实例
    autodiscovery_api(json_data=server_list, object_id='OPENSTACK_SERVERS', pks=['name'], upsert=True)
    # 子网
    autodiscovery_api(json_data=duplicated(subnet_list), object_id='OPENSTACK_SUBNET', pks=['name'], upsert=True)
    # 端口
    autodiscovery_api(json_data=duplicated(port_list), object_id='OPENSTACK_PORT', pks=['name'], upsert=True)
    # 路由
    autodiscovery_api(json_data=duplicated(router_list), object_id='OPENSTACK_ROUTER', pks=['name'], upsert=True)
    # 硬盘
    autodiscovery_api(json_data=duplicated(volumes_list), object_id='OPENSTACK_STORAGE', pks=['name'], upsert=True)