# 不需要的字段就不要填写 value
ResultKeys = {
    "IP": "ip",  # ip
    "Name": "name",  # ip
    "netSnmp": "netSnmp",  # SNMP是否能通
    "updateTime": "updateTime",  # 更新时间
    "sysVersion": "sysVersion",  # 版本
    "Model": "sysModel",  # 型号
    "sysName": "sname",  # 设备名称
    "sysDescr": "sysdescr",  # 设备描述
    "SN": "sn",  # 序列号
    "Brand": "brand",  # 品牌
    "dev_upTime": "",  # 设备启动时间
    "NetPort": "port_list",  # 网络设备端口

}
# 网络设备端口
ipAdEntKeys = {
    "Name": "name",  # 端口标识
    "IfName": "if_name",  # 端口名
    "Type": "type",  # 类型
    "OperStatus": "oper_status",  # OperStatus
    "AdminStatus": "admin_status",  # AdminStatus
    "PhysAddr": "phys_addr",  # 物理地址
    "Speed": "speed",  # 协商速率
    "MTU": "mtu",  # mtu
    "RemoteList": "remote_list",  # 对端列表
    "VLAN": "vlan",  #
    "IfIdx": "ifIdx",  # 接口号
}
# 对端列表
RemoteKeys = {
    "Name": "name",  # 标识符
    "PeerMac": "peer_mac",  # 物理地址
    "PeerDevoce": "peer_device",  # 设备
    "PeerPort": "peer_port",  # 端口
    "PeerPortDesc": "peer_port",  # 端口描述
    "PeerType": "peer_type",  # 端口类型
    "PeerIp": "",  # ip
}
# IP地址
IpAddressKeys = {
    "Name": "name",  # IP地址
    # "Status": "status",  # 是否分配 : 已分配; 未分配; 预分配
    "Mac": "mac",  #
    "Used": "used",
}