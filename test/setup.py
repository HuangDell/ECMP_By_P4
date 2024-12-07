import socket
import sys
import os
import time
import math

TYPE = 'TEST'


fp_port_configs = [
                ('1/0', '40G', 'NONE', 2),  # lumos ens2f1
                ('2/0', '40G', 'NONE', 2),  # hajime enp6s0f1
                ('3/0', '100G', 'RS', 2),  # monitoring patronus ens1f1
                ('4/0', '40G', 'NONE', 2),  # hajime enp6s0f1
                ]

def add_port_config(port_config):
    speed_dict = {'10G':'BF_SPEED_10G', '25G':'BF_SPEED_25G', '40G':'BF_SPEED_40G','50G':'BF_SPEED_50G', '100G':'BF_SPEED_100G'}
    fec_dict = {'NONE':'BF_FEC_TYP_NONE', 'FC':'BF_FEC_TYP_FC', 'RS':'BF_FEC_TYP_RS'}
    an_dict = {0:'PM_AN_DEFAULT', 1:'PM_AN_FORCE_ENABLE', 2:'PM_AN_FORCE_DISABLE'}
    lanes_dict = {'10G':(0,1,2,3), '25G':(0,1,2,3), '40G':(0,), '50G':(0,2), '100G':(0,)}
    
    # extract and map values from the config first
    conf_port = int(port_config[0].split('/')[0])
    lane = port_config[0].split('/')[1]
    conf_speed = speed_dict[port_config[1]]
    conf_fec = fec_dict[port_config[2]]
    conf_an = an_dict[port_config[3]]


    if lane == '-': # need to add all possible lanes
        lanes = lanes_dict[port_config[1]]
        for lane in lanes:
            dp = bfrt.port.port_hdl_info.get(CONN_ID=conf_port, CHNL_ID=lane, print_ents=False).data[b'$DEV_PORT']
            bfrt.port.port.add(DEV_PORT=dp, SPEED=conf_speed, FEC=conf_fec, AUTO_NEGOTIATION=conf_an, PORT_ENABLE=True)
    else: # specific lane is requested
        conf_lane = int(lane)
        dp = bfrt.port.port_hdl_info.get(CONN_ID=conf_port, CHNL_ID=conf_lane, print_ents=False).data[b'$DEV_PORT']
        bfrt.port.port.add(DEV_PORT=dp, SPEED=conf_speed, FEC=conf_fec, AUTO_NEGOTIATION=conf_an, PORT_ENABLE=True)

# for config in fp_port_configs:
#     add_port_config(config)



def add_letitflow_forward():
    l2_forward = bfrt.let_it_flow.pipe.SwitchIngress.random_forward
    def generate_port_forward(dst_addr,port_begin,port_end):
        for i in range(port_begin,port_end+1):
            l2_forward.add_with_forward(dst_addr=dst_addr,port_index=i-port_begin,port=i)
    # Add entries to the l2_forward table
    generate_port_forward(0x123456789012,1,4)
    generate_port_forward(0xAABBCCDDEEFF,5,8)
    generate_port_forward(0x112233445566,9,12)


def add_arp():
    # ARP
    bfrt.pre.node.add(MULTICAST_NODE_ID=0, MULTICAST_RID=0, MULTICAST_LAG_ID=[], DEV_PORT=active_dev_ports)
    bfrt.pre.mgid.add(MGID=1, MULTICAST_NODE_ID=[0], MULTICAST_NODE_L1_XID_VALID=[False], MULTICAST_NODE_L1_XID=[0])



if TYPE=='TEST':
    add_letitflow_forward()
    print('setup over')







