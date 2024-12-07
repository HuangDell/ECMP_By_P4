
from scapy.all import *

class BTH(Packet):
    name = "BTH"
    fields_desc = [
        BitField("opcode", 0, 8),
        BitField("se", 0, 1),
        BitField("m", 0, 1),
        BitField("pad_count", 0, 2),
        BitField("transport_hdr_version", 0, 4),
        ShortField("partition_key", 0),
        BitField("reserved", 0, 8),
        BitField("dest_qp", 0, 24),
        XIntField("psn", 0),
    ]

class RoCEPayload(Packet):
    name = "RoCEPayload"
    fields_desc = [
        IntField("sequence", 0),
        StrField("message", "")
    ]

# 定义三个不同的目标MAC地址
dst_macs = ["12:34:56:78:90:12", 
            # "AA:BB:CC:DD:EE:FF", 
            # "11:22:33:44:55:66"
            ]

# 源MAC地址和IP地址
src_mac = "00:11:22:33:44:55"
src_ip = "192.168.1.1"
dst_ip = "192.168.1.2"

# 创建基础包结构
ip = IP(dst=dst_ip, src=src_ip)
udp = UDP(dport=4791, sport=12345)
bth = BTH(opcode=0x04, dest_qp=0x1)

# 发送10个报文
for i in range(3):
    # 选择目标MAC地址 (轮换使用)
    dst_mac = dst_macs[i % len(dst_macs)]
    
    # 创建以太网帧
    eth = Ether(dst=dst_mac, src=src_mac)
    
    # 创建RoCE payload，包含序号和消息
    roce_payload = RoCEPayload(sequence=i+1, message=f"Packet {i+1} to {dst_mac}")
    
    # 组装完整的包
    packet = eth / ip / udp / bth / roce_payload
    
    # 显示包的内容
    print(f"\nSending packet {i+1} to {dst_mac}:")
    
    # 发送包
    sendp(packet, iface="veth0", verbose=False)

print("\nAll packets sent successfully.")
