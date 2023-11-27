#  Copyright (c) 2023 fanqin. Lorem ipsum dolor sit amet, consectetur adipiscing elit.
#  Morbi non lorem porttitor neque feugiat blandit. Ut vitae ipsum eget quam lacinia accumsan.
#  Etiam sed turpis ac ipsum condimentum fringilla. Maecenas magna.
#  Proin dapibus sapien vel ante. Aliquam erat volutpat. Pellentesque sagittis ligula eget metus.
#  Vestibulum commodo. Ut rhoncus gravida arcu.

import csv

from scapy.all import *
from scapy.layers.inet import IP, TCP
from scapy.layers.tls.record import TLS
import multiprocessing
import os
import shutil
from FileUtil import get_subdirectories, get_pcap_files, get_csv_files, get_csv_rows, merge_csv_files, \
    split_dataset, shuffle_large_csv_file

load_layer("tls")


def encode_pcap_folder(raw_foler, packet_max_count=-1):
    # 获取当前设备的CPU数量
    cpu_count = multiprocessing.cpu_count()
    if cpu_count < 1:
        cpu_count = 1
    print("The current number of computer cpus is: ", cpu_count)
    # 开启线程池
    pool = multiprocessing.Pool(processes=int(cpu_count))
    subdirectories = get_subdirectories(raw_foler)
    value_label = 0
    for subdirectory in subdirectories:
        print("Converting folder \"" + str(subdirectory) + "\" to .CSV file format...")
        # 遍历所有文件，找到以 ".pcap" 结尾的文件
        pcap_files = get_pcap_files(raw_foler + os.sep + subdirectory)
        # 将文件夹名设置为标签
        pcap_label = os.path.basename(subdirectory)
        label_dict[pcap_label] = value_label
        for pcap_file in pcap_files:
            # 输出文件路径
            csv_file = pcap_file + '.csv'
            # 使用多进程进行并发处理
            pool.apply_async(process_pcap_file_to_csv, (pcap_file, csv_file, value_label, packet_max_count))
        value_label = int(value_label) + 1
        value_label = int(value_label)
    pool.close()
    pool.join()  # 调用join之前，先调用close函数，否则会出错。执行完close后不会有新的进程加入到pool,join函数等待所有子进程结束
    return raw_foler


def generate_train_val_data(raw_foler, train_ratio=0.8):
    sample_count = 0
    # 先统计总的数据数量
    subdirectories = get_subdirectories(raw_foler)
    for subdirectory in subdirectories:
        print("INFO::Counting folder \"" + str(subdirectory) + "\"...")
        # 遍历所有文件，找到以 ".csv" 结尾的文件
        csv_files = get_csv_files(raw_foler + os.sep + subdirectory)
        for csv_file in csv_files:
            sample_count = sample_count + get_csv_rows(csv_file)
    print("INFO::Sample count is " + str(sample_count))
    # 合并CSV文件
    temp_merge_csv_dir = os.path.dirname(raw_foler) + os.sep + "temp"
    if not os.path.exists(temp_merge_csv_dir):
        os.makedirs(temp_merge_csv_dir)
    merge_csv_path = merge_csv_files(raw_foler, temp_merge_csv_dir)

    # 打乱
    print(merge_csv_path)
    shuffle_large_csv_file(merge_csv_path)
    # 然后更具比例进行划分
    if not os.path.exists(train_foler):
        os.makedirs(train_foler)
    if not os.path.exists(val_foler):
        os.makedirs(val_foler)
    output_train_path = train_foler + os.sep + "train.csv"
    output_val_path = val_foler + os.sep + "val.csv"
    split_dataset(merge_csv_path, output_train_path, output_val_path, train_ratio)

    print(temp_merge_csv_dir)
    if os.path.exists(temp_merge_csv_dir):
        shutil.rmtree(temp_merge_csv_dir)
    print("INFO::Generate dataset successfully.")


def process_pcap_file_to_csv(pcap_file, csv_file, label, packet_max_count=-1):
    line_length = 0
    save_file = open(csv_file, 'w+', encoding='utf-8', newline='')
    writer = csv.writer(save_file)

    ##############################################################
    ######################### Header #############################
    ##############################################################

    ip_header = [
        "ip_version_0",
        "ip_version_1",
        "ip_version_2",
        "ip_version_3",

        "ip_ihl_0",
        "ip_ihl_1",
        "ip_ihl_2",
        "ip_ihl_3",

        "ip_tos_0",
        "ip_tos_1",
        "ip_tos_2",
        "ip_tos_3",
        "ip_tos_4",
        "ip_tos_5",
        "ip_tos_6",
        "ip_tos_7",

        "ip_len_0",
        "ip_len_1",
        "ip_len_2",
        "ip_len_3",
        "ip_len_4",
        "ip_len_5",
        "ip_len_6",
        "ip_len_7",
        "ip_len_8",
        "ip_len_9",
        "ip_len_10",
        "ip_len_11",
        "ip_len_12",
        "ip_len_13",
        "ip_len_14",
        "ip_len_15",

        "ip_id_0",
        "ip_id_1",
        "ip_id_2",
        "ip_id_3",
        "ip_id_4",
        "ip_id_5",
        "ip_id_6",
        "ip_id_7",
        "ip_id_8",
        "ip_id_9",
        "ip_id_10",
        "ip_id_11",
        "ip_id_12",
        "ip_id_13",
        "ip_id_14",
        "ip_id_15",

        "ip_flags_0",
        "ip_flags_1",
        "ip_flags_2",

        "ip_frag_0",
        "ip_frag_1",
        "ip_frag_2",
        "ip_frag_3",
        "ip_frag_4",
        "ip_frag_5",
        "ip_frag_6",
        "ip_frag_7",
        "ip_frag_8",
        "ip_frag_9",
        "ip_frag_10",
        "ip_frag_11",
        "ip_frag_12",

        "ip_ttl_0",
        "ip_ttl_1",
        "ip_ttl_2",
        "ip_ttl_3",
        "ip_ttl_4",
        "ip_ttl_5",
        "ip_ttl_6",
        "ip_ttl_7",

        "ip_proto_0",
        "ip_proto_1",
        "ip_proto_2",
        "ip_proto_3",
        "ip_proto_4",
        "ip_proto_5",
        "ip_proto_6",
        "ip_proto_7",

        "ip_chksum_0",
        "ip_chksum_1",
        "ip_chksum_2",
        "ip_chksum_3",
        "ip_chksum_4",
        "ip_chksum_5",
        "ip_chksum_6",
        "ip_chksum_7",
        "ip_chksum_8",
        "ip_chksum_9",
        "ip_chksum_10",
        "ip_chksum_11",
        "ip_chksum_12",
        "ip_chksum_13",
        "ip_chksum_14",
        "ip_chksum_15",

        "ip_src_0",
        "ip_src_1",
        "ip_src_2",
        "ip_src_3",
        "ip_src_4",
        "ip_src_5",
        "ip_src_6",
        "ip_src_7",
        "ip_src_8",
        "ip_src_9",
        "ip_src_10",
        "ip_src_11",
        "ip_src_12",
        "ip_src_13",
        "ip_src_14",
        "ip_src_15",
        "ip_src_16",
        "ip_src_17",
        "ip_src_18",
        "ip_src_19",
        "ip_src_20",
        "ip_src_21",
        "ip_src_22",
        "ip_src_23",
        "ip_src_24",
        "ip_src_25",
        "ip_src_26",
        "ip_src_27",
        "ip_src_28",
        "ip_src_29",
        "ip_src_30",
        "ip_src_31",

        "ip_dst_0",
        "ip_dst_1",
        "ip_dst_2",
        "ip_dst_3",
        "ip_dst_4",
        "ip_dst_5",
        "ip_dst_6",
        "ip_dst_7",
        "ip_dst_8",
        "ip_dst_9",
        "ip_dst_10",
        "ip_dst_11",
        "ip_dst_12",
        "ip_dst_13",
        "ip_dst_14",
        "ip_dst_15",
        "ip_dst_16",
        "ip_dst_17",
        "ip_dst_18",
        "ip_dst_19",
        "ip_dst_20",
        "ip_dst_21",
        "ip_dst_22",
        "ip_dst_23",
        "ip_dst_24",
        "ip_dst_25",
        "ip_dst_26",
        "ip_dst_27",
        "ip_dst_28",
        "ip_dst_29",
        "ip_dst_30",
        "ip_dst_31"
    ]

    tcp_header = [
        "tcp_sport_0",
        "tcp_sport_1",
        "tcp_sport_2",
        "tcp_sport_3",
        "tcp_sport_4",
        "tcp_sport_5",
        "tcp_sport_6",
        "tcp_sport_7",
        "tcp_sport_8",
        "tcp_sport_9",
        "tcp_sport_10",
        "tcp_sport_11",
        "tcp_sport_12",
        "tcp_sport_13",
        "tcp_sport_14",
        "tcp_sport_15",

        "tcp_dport_0",
        "tcp_dport_1",
        "tcp_dport_2",
        "tcp_dport_3",
        "tcp_dport_4",
        "tcp_dport_5",
        "tcp_dport_6",
        "tcp_dport_7",
        "tcp_dport_8",
        "tcp_dport_9",
        "tcp_dport_10",
        "tcp_dport_11",
        "tcp_dport_12",
        "tcp_dport_13",
        "tcp_dport_14",
        "tcp_dport_15",

        "tcp_seq_0",
        "tcp_seq_1",
        "tcp_seq_2",
        "tcp_seq_3",
        "tcp_seq_4",
        "tcp_seq_5",
        "tcp_seq_6",
        "tcp_seq_7",
        "tcp_seq_8",
        "tcp_seq_9",
        "tcp_seq_10",
        "tcp_seq_11",
        "tcp_seq_12",
        "tcp_seq_13",
        "tcp_seq_14",
        "tcp_seq_15",
        "tcp_seq_16",
        "tcp_seq_17",
        "tcp_seq_18",
        "tcp_seq_19",
        "tcp_seq_20",
        "tcp_seq_21",
        "tcp_seq_22",
        "tcp_seq_23",
        "tcp_seq_24",
        "tcp_seq_25",
        "tcp_seq_26",
        "tcp_seq_27",
        "tcp_seq_28",
        "tcp_seq_29",
        "tcp_seq_30",
        "tcp_seq_31",

        "tcp_ack_0",
        "tcp_ack_1",
        "tcp_ack_2",
        "tcp_ack_3",
        "tcp_ack_4",
        "tcp_ack_5",
        "tcp_ack_6",
        "tcp_ack_7",
        "tcp_ack_8",
        "tcp_ack_9",
        "tcp_ack_10",
        "tcp_ack_11",
        "tcp_ack_12",
        "tcp_ack_13",
        "tcp_ack_14",
        "tcp_ack_15",
        "tcp_ack_16",
        "tcp_ack_17",
        "tcp_ack_18",
        "tcp_ack_19",
        "tcp_ack_20",
        "tcp_ack_21",
        "tcp_ack_22",
        "tcp_ack_23",
        "tcp_ack_24",
        "tcp_ack_25",
        "tcp_ack_26",
        "tcp_ack_27",
        "tcp_ack_28",
        "tcp_ack_29",
        "tcp_ack_30",
        "tcp_ack_31",

        "tcp_dataofs_0",
        "tcp_dataofs_1",
        "tcp_dataofs_2",
        "tcp_dataofs_3",

        "tcp_reserveds_0",
        "tcp_reserveds_1",
        "tcp_reserveds_2",
        "tcp_reserveds_3",
        "tcp_reserveds_4",
        "tcp_reserveds_5",

        "tcp_flags_0",
        "tcp_flags_1",
        "tcp_flags_2",
        "tcp_flags_3",
        "tcp_flags_4",
        "tcp_flags_5",

        "tcp_window_0",
        "tcp_window_1",
        "tcp_window_2",
        "tcp_window_3",
        "tcp_window_4",
        "tcp_window_5",
        "tcp_window_6",
        "tcp_window_7",
        "tcp_window_8",
        "tcp_window_9",
        "tcp_window_10",
        "tcp_window_11",
        "tcp_window_12",
        "tcp_window_13",
        "tcp_window_14",
        "tcp_window_15",

        "tcp_chksum_0",
        "tcp_chksum_1",
        "tcp_chksum_2",
        "tcp_chksum_3",
        "tcp_chksum_4",
        "tcp_chksum_5",
        "tcp_chksum_6",
        "tcp_chksum_7",
        "tcp_chksum_8",
        "tcp_chksum_9",
        "tcp_chksum_10",
        "tcp_chksum_11",
        "tcp_chksum_12",
        "tcp_chksum_13",
        "tcp_chksum_14",
        "tcp_chksum_15",

        "tcp_urgptr_0",
        "tcp_urgptr_1",
        "tcp_urgptr_2",
        "tcp_urgptr_3",
        "tcp_urgptr_4",
        "tcp_urgptr_5",
        "tcp_urgptr_6",
        "tcp_urgptr_7",
        "tcp_urgptr_8",
        "tcp_urgptr_9",
        "tcp_urgptr_10",
        "tcp_urgptr_11",
        "tcp_urgptr_12",
        "tcp_urgptr_13",
        "tcp_urgptr_14",
        "tcp_urgptr_15"
    ]

    tls_header = [
        "tls_type_0",
        "tls_type_1",
        "tls_type_2",
        "tls_type_3",
        "tls_type_4",
        "tls_type_5",
        "tls_type_6",
        "tls_type_7",

        "tls_version_0",
        "tls_version_1",
        "tls_version_2",
        "tls_version_3",
        "tls_version_4",
        "tls_version_5",
        "tls_version_6",
        "tls_version_7",
        "tls_version_8",
        "tls_version_9",
        "tls_version_10",
        "tls_version_11",
        "tls_version_12",
        "tls_version_13",
        "tls_version_14",
        "tls_version_15",

        "tls_len_0",
        "tls_len_1",
        "tls_len_2",
        "tls_len_3",
        "tls_len_4",
        "tls_len_5",
        "tls_len_6",
        "tls_len_7",
        "tls_len_8",
        "tls_len_9",
        "tls_len_10",
        "tls_len_11",
        "tls_len_12",
        "tls_len_13",
        "tls_len_14",
        "tls_len_15",
    ]
    header = ip_header + tcp_header + tls_header
    header.append("label")

    if line_length == 0:
        line_length = len(header)
    writer.writerow(header)
    if not (pcap_file.lower().endswith(".pcap")):
        print("\033[1;32m", "File " + pcap_file + " is not PCAP...Skipped.", "\033[0m")
        return
    pkts = rdpcap(pcap_file, count=packet_max_count)
    for pkt in pkts:
        # print(pkt.show())
        if (IP not in pkt) or (TCP not in pkt) or (TLS not in pkt):
            continue
        try:
            line = []
            ##############################################################
            ############################ IP ##############################
            ##############################################################
            # IP-version
            ip_version = pkt['IP'].fields['version']
            ip_version_formated = '{:04b}'.format(ip_version)
            for binary in ip_version_formated:
                line.append(int(binary))

            # IP-ihl
            ip_ihl = pkt['IP'].fields['ihl']
            ip_ihl_formated = '{:04b}'.format(ip_ihl)
            for binary in ip_ihl_formated:
                line.append(int(binary))

            # IP-tos
            ip_tos = pkt['IP'].fields['tos']
            ip_tos_formated = '{:08b}'.format(ip_tos)
            for binary in ip_tos_formated:
                line.append(int(binary))

            # IP-len
            ip_len = pkt['IP'].fields['len']
            ip_len_formated = '{:016b}'.format(ip_len)
            for binary in ip_len_formated:
                line.append(int(binary))

            # IP-id
            ip_id = pkt['IP'].fields['id']
            ip_id_formated = '{:016b}'.format(ip_id)
            for binary in ip_id_formated:
                line.append(int(binary))

            # IP-flags
            ip_flags = pkt['IP'].fields['flags']
            if ip_flags == "DF":
                ip_flags = 2
            elif ip_flags == "MF":
                ip_flags = 1
            else:
                ip_flags = 0
            ip_flags_formated = '{:03b}'.format(ip_flags)
            for binary in ip_flags_formated:
                line.append(int(binary))

            # IP-frag
            ip_frag = pkt['IP'].fields['frag']
            ip_frag_formated = '{:013b}'.format(ip_frag)
            for binary in ip_frag_formated:
                line.append(int(binary))

            # IP-ttl
            ip_ttl = pkt['IP'].fields['ttl']
            ip_ttl_formated = '{:08b}'.format(ip_ttl)
            for binary in ip_ttl_formated:
                line.append(int(binary))

            # IP-proto
            ip_proto = pkt['IP'].fields['proto']
            ip_proto_formated = '{:08b}'.format(ip_proto)
            for binary in ip_proto_formated:
                line.append(int(binary))

            # IP-chksum
            ip_chksum = pkt['IP'].fields['chksum']
            ip_chksum_formated = '{:016b}'.format(ip_chksum)
            for binary in ip_chksum_formated:
                line.append(int(binary))

            # IP-src
            ip_src = pkt['IP'].fields['src']
            ip_srcs = ip_src.split(".")
            for part in ip_srcs:
                part_formated = '{:08b}'.format(int(part))
                for binary in part_formated:
                    line.append(int(binary))

            # IP-dst
            ip_dst = pkt['IP'].fields['dst']
            ip_dsts = ip_dst.split(".")
            for part in ip_dsts:
                part_formated = '{:08b}'.format(int(part))
                for binary in part_formated:
                    line.append(int(binary))

            ##############################################################
            ############################ TCP ##############################
            ##############################################################
            if TCP not in pkt:
                continue
            # sport
            tcp_sport = '{:016b}'.format(pkt['TCP'].fields['sport'])
            for tcp_s in tcp_sport:
                line.append(int(tcp_s))
            # dport
            tcp_dport = '{:016b}'.format(pkt['TCP'].fields['dport'])
            for tcp_d in tcp_dport:
                line.append(int(tcp_d))
            # seq
            tcp_seq = '{:032b}'.format(pkt['TCP'].fields['seq'])
            for tcp_s in tcp_seq:
                line.append(int(tcp_s))
            # ack
            tcp_ack = '{:032b}'.format(pkt['TCP'].fields['ack'])
            for tcp_a in tcp_ack:
                line.append(int(tcp_a))
            # dataofs
            tcp_dataofs = '{:04b}'.format(pkt['TCP'].fields['dataofs'])
            for tcp_d in tcp_dataofs:
                line.append(int(tcp_d))
            # reserved
            tcp_reserved = '{:06b}'.format(pkt['TCP'].fields['reserved'])
            for tcp_r in tcp_reserved:
                line.append(int(tcp_r))
            # flags
            tcp_flags = pkt['TCP'].flags
            if 'U' in tcp_flags:
                line.append(int(1))
            else:
                line.append(int(0))
            if 'A' in tcp_flags:
                line.append(int(1))
            else:
                line.append(int(0))
            if 'P' in tcp_flags:
                line.append(int(1))
            else:
                line.append(int(0))
            if 'R' in tcp_flags:
                line.append(int(1))
            else:
                line.append(int(0))
            if 'S' in tcp_flags:
                line.append(int(1))
            else:
                line.append(int(0))
            if 'F' in tcp_flags:
                line.append(int(1))
            else:
                line.append(int(0))

            # window
            tcp_window = '{:016b}'.format(pkt['TCP'].fields['window'])
            for tcp_w in tcp_window:
                line.append(int(tcp_w))

            # chksum
            tcp_chksum = '{:016b}'.format(pkt['TCP'].fields['chksum'])
            for tcp_c in tcp_chksum:
                line.append(int(tcp_c))

            # urgptr
            tcp_urgptr = '{:016b}'.format(pkt['TCP'].fields['urgptr'])
            for tcp_u in tcp_urgptr:
                line.append(int(tcp_u))

            # options fix me

            ##############################################################
            ############################ TLS #############################
            ##############################################################
            # type
            tls_type = '{:08b}'.format(pkt['TLS'].fields['type'])
            for tls_t in tls_type:
                line.append(int(tls_t))

            # version
            tls_version = '{:016b}'.format(pkt['TLS'].fields['version'])
            for tls_v in tls_version:
                line.append(int(tls_v))

            # len
            tls_len = '{:016b}'.format(pkt['TLS'].fields['len'])
            for tls_l in tls_len:
                line.append(int(tls_l))

            ##############################################################
            ############################ Label ###########################
            ##############################################################
            line.append(label)

            if line_length != len(line):
                print(f'line length is not same: {line}')
            else:
                writer.writerow(line)
        except Exception as e:
            print(f'except:{e}')
            continue


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    # 原始数据集文件
    raw_foler = r"C:\Users\fanqi\Documents\GitHub\AutoDNS\Code\AutoDNS\data\DoHBrw-2020\Raw"

    # 生成数据集文件夹
    dataset_folder = r"C:\Users\fanqi\Documents\GitHub\AutoDNS\Code\AutoDNS\code\AutoPrint\Dataset\DoHBrw-2020"

    # 训练数据集文件夹
    train_foler = dataset_folder + os.sep + "train"
    # 验证数据集文件夹
    val_foler = dataset_folder + os.sep + "val"

    label_dict = {}

    # 提取PCAP数据包的时候，从单个PCAP文件提取的最大包数，设置为-1的时候不限制
    packet_max_count = -1

    raw_foler = encode_pcap_folder(raw_foler, packet_max_count)
    generate_train_val_data(raw_foler)
