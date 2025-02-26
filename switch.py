#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

trunk_interfaces = []
port_states = {}
root_bridge_ID = None
own_bridge_ID =  None
root_path_cost = 0
root_port = None
trunk_mapping = {}

def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    #dest_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])
    dest_mac = data[0:6]
    src_mac = data[6:12]

    # Extract ethertype. Under 802.1Q, this may be the bytes from the VLAN TAG
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    # Check for VLAN tag (0x8100 in network byte order is b'\x81\x00')
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF  # extract the 12-bit VLAN ID
        ether_type = (data[16] << 8) + data[17]

    return dest_mac, src_mac, ether_type, vlan_id

def create_vlan_tag(vlan_id):
    # 0x8100 for the Ethertype for 802.1Q
    # vlan_id & 0x0FFF ensures that only the last 12 bits are used
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)

def create_bpdu_frame(cost):
    dsap = 0x42
    ssap = 0x42
    control = 0x03

    llc_header = struct.pack('!BBB', dsap, ssap, control)

    # the bpdu config structure contains the root bridge id the root path cost and the sender bridge id
    bpdu_config = struct.pack('!8sI8s', str(root_bridge_ID).encode('utf-8'), cost, str(own_bridge_ID).encode('utf-8'))
    switch_mac = get_switch_mac()
    dest_mac = b'\x01\x80\xc2\x00\x00\x00'
    llc_length = len(llc_header) + len(bpdu_config)
    bpdu_frame = dest_mac + switch_mac + str(llc_length).encode('utf-8') + llc_header + bpdu_config

    return bpdu_frame

def send_bdpu_every_sec():
    while True:
        if own_bridge_ID == root_bridge_ID:
            bpdu_frame= create_bpdu_frame(0)         
            for trunk in trunk_interfaces:
                send_to_link(trunk_mapping[trunk], len(bpdu_frame), bpdu_frame)
        time.sleep(1)

def read_config(switch_id):
    global trunk_interfaces

    vlan_id_table = {}
    filename = "configs/switch" + str(switch_id) + ".cfg"

    with open(filename, "r") as f:
        priority = int(f.readline())
        for line in f:
            line = line.strip().split()

            # we keep trunk interfaces names in trunk_interfaces
            if line[1] == 'T':
                vlan_id_table[line[0]] = line[1]
                trunk_interfaces.append(line[0])
            else:
                vlan_id_table[line[0]] = int(line[1])

    return priority, vlan_id_table

def do_comutation_process(interface, interfaces, vlan_id, length, data, dest_mac, mac_table, vlan_id_table):
    # received from acces port
    if vlan_id == -1:
        src_vlan_id = vlan_id_table[get_interface_name(interface)]
        if dest_mac in mac_table and dest_mac != "ff:ff:ff:ff:ff:ff":                    
            dest_vlan_id = vlan_id_table[get_interface_name(mac_table[dest_mac])]    

            if src_vlan_id == dest_vlan_id:
                send_to_link(mac_table[dest_mac], length, data)
            # if the frame needs to be sent on a trunk port we add the source vlan id
            elif dest_vlan_id == 'T':
                send_to_link(mac_table[dest_mac], length + 4, data[0:12] + create_vlan_tag(src_vlan_id) + data[12:])
        else:
            for i in interfaces:
                if i != interface:
                    dest_vlan_id = vlan_id_table[get_interface_name(i)]
                    
                    if src_vlan_id == dest_vlan_id:
                        send_to_link(i, length, data)
                    # we send the frame on all trunk ports that aren't blocked and we add the source vlan id
                    elif dest_vlan_id == 'T' and port_states[get_interface_name(i)] != "BLOCKING":
                        send_to_link(i, length + 4, data[0:12] + create_vlan_tag(src_vlan_id) + data[12:])
    # received from trunk port
    else:
        if dest_mac in mac_table and dest_mac != "ff:ff:ff:ff:ff:ff":
            dest_vlan_id = vlan_id_table[get_interface_name(mac_table[dest_mac])]

            # if we need to send on an access port we remove the vlan id from the frame
            if vlan_id == dest_vlan_id:
                send_to_link(mac_table[dest_mac], length - 4, data[0:12] + data[16:])
            elif dest_vlan_id == 'T':
                send_to_link(mac_table[dest_mac], length, data)
        else:
            for i in interfaces:
                if i != interface:
                    dest_vlan_id = vlan_id_table[get_interface_name(i)]

                    # we send the frame on all access ports from the same vlan and we remove the vlan id
                    if vlan_id == dest_vlan_id:
                        send_to_link(i, length - 4, data[0:12] + data[16:])
                    # we send the frame on all trunk ports that aren't blocked
                    elif dest_vlan_id == 'T' and port_states[get_interface_name(i)] != "BLOCKING":
                        send_to_link(i, length, data)

def do_stp(interface, data):
    global port_states, root_bridge_ID, own_bridge_ID, root_path_cost, root_port

    # extract bpdu information from data
    bpdu_root_bridge_id, bpdu_sender_path_cost, bpdu_sender_bridge_id = struct.unpack('!8sI8s', data[17:])

    # convert the root and sender id back to int values
    bpdu_root_id = int(bpdu_root_bridge_id.split(b'\x00')[0].decode()) 
    bpdu_sender_id = int(bpdu_sender_bridge_id.split(b'\x00')[0].decode()) 

    if bpdu_root_id < root_bridge_ID:
        # save the previous root id
        previous_root_bridge_id = root_bridge_ID
        root_bridge_ID = bpdu_root_id
        root_path_cost = bpdu_sender_path_cost + 10
        root_port = get_interface_name(interface)

        # check if the bridge was previously root
        if own_bridge_ID == previous_root_bridge_id:
            for trunk in trunk_interfaces:
                if trunk != root_port:
                    port_states[trunk] = "BLOCKING"

        if port_states[root_port] == "BLOCKING":
            port_states[root_port] = "LISTENING"

        bpdu_packet = create_bpdu_frame(root_path_cost) 
                
        for trunk in trunk_interfaces:
            if trunk != get_interface_name(interface):
                send_to_link(trunk_mapping[trunk], len(bpdu_packet), bpdu_packet)
    elif bpdu_root_id == root_bridge_ID:
        if get_interface_name(interface) == root_port and bpdu_sender_path_cost + 10 < root_path_cost:
            root_path_cost = bpdu_sender_path_cost + 10
    elif get_interface_name(interface) != root_port:
        if bpdu_sender_path_cost > root_path_cost:
            if port_states[get_interface_name(interface)] != "DESIGNATED_PORT":
                port_states[get_interface_name(interface)] = "LISTENING"
    elif bpdu_sender_id == own_bridge_ID:
        port_states[get_interface_name(interface)] = "BLOCKING"
            
    if own_bridge_ID == root_bridge_ID:
        for trunk in trunk_interfaces:
            port_states[trunk] = "DESIGNATED_PORT"

def main():
    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]

    mac_table = {}
    priority, vlan_id_table = read_config(switch_id)

    global port_states, root_bridge_ID, own_bridge_ID, root_path_cost, root_port, trunk_mapping

    for trunk in trunk_interfaces:
        port_states[trunk] = "BLOCKING"

    own_bridge_ID =  priority
    root_bridge_ID = own_bridge_ID
    root_path_cost = 0

    if own_bridge_ID == root_bridge_ID:
        for trunk in trunk_interfaces:
            port_states[trunk] = "DESIGNATED_PORT"

    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)

    # mapping for name and number of trunk interfaces
    for i in interfaces:
        if get_interface_name(i) in trunk_interfaces:
            trunk_mapping[get_interface_name(i)] = i

    # Create and start a new thread that deals with sending BDPU
    t = threading.Thread(target=send_bdpu_every_sec)
    t.start()

    while True:
        # Note that data is of type bytes([...]).
        # b1 = bytes([72, 101, 108, 108, 111])  # "Hello"
        # b2 = bytes([32, 87, 111, 114, 108, 100])  # " World"
        # b3 = b1[0:2] + b[3:4].
        interface, data, length = recv_from_any_link()

        dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)

        # Print the MAC src and MAC dst in human readable format
        dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
        src_mac = ':'.join(f'{b:02x}' for b in src_mac)

        # if dest mac is 01:80:c2:00:00:00 the frame contains bpdu information
        if dest_mac == "01:80:c2:00:00:00":
            do_stp(interface, data)
        # else we do the comutation process
        else:
            mac_table[src_mac] = interface
            do_comutation_process(interface, interfaces, vlan_id, length, data, dest_mac, mac_table, vlan_id_table)                           

if __name__ == "__main__":
    main()

