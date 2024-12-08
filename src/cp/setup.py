import socket
import sys
import os
import time
import math

# mirroring interfaces for P4-2
INFO_DEV_PORT_PATRONUS_ENS1F1 = 156
MIRROR_SESSION_RDMA_SNIFF_IG = 777 # mirroring's session id for sniffing RDMA packets for IG_MIRROR 

hostname = socket.gethostname()
print("Hostname: {}".format(hostname))
fp_port_configs=None
l2_forward_configs=None
active_dev_ports = None

if hostname == 'P4-2':
    fp_port_configs = [
                    ('2/0', '100G', 'NONE', 2),  # P4-2 2 port --> 116 1 port  
                    ('4/0', '100G', 'RS', 2),   # P4-2 4 port --> 112 1 port for mirror
                    ('5/-', '25G', 'NONE', 2),  # P4-2 5 port --> P4-1 5 port
                    ]
    l2_forward_configs =[
        (0xe8ebd358a02c,140,140),   # to 116 host
        (0xe8ebd358a0bc,156,156),    # to 112 host for mirroring
        (0xe8ebd358a0cd,164,167),   # to 114 host via P4-1
        (0x0180c2000001,140,140),   # PFC to 116 host
    ]

elif hostname == 'P4-1':
    fp_port_configs = [
                    ('1/0', '100G', 'NONE', 2),  # P4-1 1 port --> 114 2 port 
                    ('5/-', '25G', 'NONE', 2),  # P4-1 5 port --> P4-2 5 port
                    ]

    l2_forward_configs =[
        (0xe8ebd358a02c,160,163),   # to 116 host via P4-2
        (0xe8ebd358a0cd,128,128),   # to 114 host 

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



def add_l2_forward(forward_configs):
    l2_forward = bfrt.ecmp.pipe.SwitchIngress.ecmp_forward
    def generate_random_port_forward(dst_addr,port_begin,port_end):
        for i in range(port_begin,port_end+1):
            l2_forward.add_with_forward(dst_addr=dst_addr,port_index=i-port_begin,port=i)
    
    for config in forward_configs:
            generate_random_port_forward(*config)

    

def add_arp(dev_ports):
    # ARP
    bfrt.pre.node.add(MULTICAST_NODE_ID=0, MULTICAST_RID=0, MULTICAST_LAG_ID=[], DEV_PORT=dev_ports)
    bfrt.pre.mgid.add(MGID=1, MULTICAST_NODE_ID=[0], MULTICAST_NODE_L1_XID_VALID=[False], MULTICAST_NODE_L1_XID=[0])




for port_config in fp_port_configs:
    add_port_config(port_config)


if hostname == "P4-2":
    bfrt.mirror.cfg.add_with_normal(sid=MIRROR_SESSION_RDMA_SNIFF_IG, direction='INGRESS', session_enable=True, ucast_egress_port=INFO_DEV_PORT_PATRONUS_ENS1F1, ucast_egress_port_valid=1, max_pkt_len=48)

add_l2_forward(l2_forward_configs)
# add_exact_forward(l2_forward_configs)
# add_arp(active_dev_ports)
print('setup over')







