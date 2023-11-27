import pandas as pd
from matplotlib import pyplot as plt
import numpy as np
import matplotlib.patches as patches

"""
排序id，
特征的名称
位大小bit
特征的重要度，
"""


class Feature:
    def __init__(self, raw, col, bit, width, weight, description, paint_description=""):
        self.raw = raw  # 所在行数
        self.col = col  # 所在列数
        self.bit = bit  # nprint占用的个数
        self.width = width  # 宽度
        self.weight = weight  # 重要性
        self.description = description
        self.paint_description = paint_description


IP_Header_With_Features = [Feature(0, 0, 4, 4, 4, "ip_version", "Version"),
                           Feature(0, 4, 4, 4, 4, "ip_ihl", "HLEN"),
                           Feature(0, 8, 8, 8, 8, "ip_tos", "Type of Service"),
                           Feature(0, 16, 16, 16, 16, "ip_len", "Total Length"),
                           Feature(1, 0, 16, 16, 16, "ip_id", "Identification"),
                           Feature(1, 16, 3, 3, 3, "ip_flags", "Flags"),
                           Feature(1, 19, 13, 13, 13, "ip_frag", "Fragment Offset"),
                           Feature(2, 0, 8, 8, 8, "ip_ttl", "Time to Live"),
                           Feature(2, 8, 8, 8, 8, "ip_proto", "Protocol"),
                           Feature(2, 16, 16, 16, 16, "ip_chksum", "Header Checksum"),
                           Feature(3, 0, 32, 32, 32, "ip_src", "Source IP"),
                           Feature(4, 0, 32, 32, 32, "ip_dst", "Destination IP"), ]

UDP_Header_With_Features = [Feature(0, 0, 16, 16, 4, "sport","Source Port"),
                            Feature(0, 16, 16, 16, 4, "dport","Destination Port"),
                            Feature(1, 0, 16, 16, 16, "len","Length"),
                            Feature(1, 16, 16, 16, 16, "chksum","Checksum"), ]

DNS_Header_With_Features = [Feature(0, 0, 16, 16, 16, "dns_identification","Identification"),
                            Feature(0, 16, 1, 1, 1, "dns_qr","qr"),
                            Feature(0, 17, 4, 4, 4, "dns_opcode","opcode"),
                            Feature(0, 21, 1, 1, 1, "dns_aa","aa"),
                            Feature(0, 22, 1, 1, 1, "dns_tc","tc"),
                            Feature(0, 23, 1, 1, 1, "dns_rd","rd"),
                            Feature(0, 24, 1, 1, 1, "dns_ra","ra"),
                            Feature(0, 25, 1, 1, 1, "dns_z","z"),
                            Feature(0, 26, 1, 1, 1, "dns_ad","ad"),
                            Feature(0, 27, 1, 1, 1, "dns_cd","cd"),
                            Feature(0, 28, 4, 4, 4, "dns_rcode","rcode"),
                            Feature(1, 0, 16, 16, 16, "dns_qdcount","QDCount"),
                            Feature(1, 16, 16, 16, 16, "dns_ancount","ANCount"),
                            Feature(2, 0, 16, 16, 16, "dns_nscount","NSCount"),
                            Feature(2, 16, 16, 16, 16, "dns_arcount","ARCount"),

                            # Body
                            Feature(3, 0, 1056, 32, 32, "dns_qd","DN"),
                            Feature(4, 0, 1072, 32, 32, "dns_an","AN"), ]


class Packet:
    def __init__(self, raw_num):
        self.raw_num = raw_num  # 行数


def check_format():
    pass


def draw_format(packet, feature_list):
    packet_raw_num = packet.raw_num
    # 创建一个行数为packet_raw_num，列数为32的数组
    array = np.array([[0] * 32] * packet_raw_num, dtype="float")
    for feature in feature_list:
        raw = feature.raw
        col = feature.col
        width = feature.width
        weight = feature.weight
        # 将第raw行，第col列的元素设置为指定的数值
        if width <= 32:
            for index in range(0, width):
                array[raw, col + index] = float(weight)
        else:
            for index_raw in range((int)(width / 32)):
                array[raw + index_raw, :] = float(weight)
    return array


def draw(data, feature_list,draw_description="Packet"):
    # 作图阶段
    fig, ax = plt.subplots(dpi=1200)  # 设置dpi为300，提高分辨率
    # 作图并选择热图的颜色填充风格，这里选择yLGn
    im = ax.imshow(data, cmap="Blues")
    # 增加右侧的颜色刻度条
    plt.colorbar(im, shrink=0.8, location="top")  # 调整shrink的值来改变刻度条的大小

    # 填充数字
    for feature in feature_list:
        raw = feature.raw
        col = feature.col
        width = feature.width
        weight = feature.weight
        description = feature.description
        paint_description = feature.paint_description
        print('data[{},{}]:{}'.format(raw, float(col +( float(width) / 2))-0.5, paint_description))
        ax.text( float(col +( float(width) / 2))-0.5, raw, paint_description,
                ha="center", va="center", color="gray", fontsize=8)
        # 添加边框
        border = patches.Rectangle((col - 0.5, raw - 0.5), width, 1, linewidth=0.3, edgecolor='black',
                                   facecolor='none')
        ax.add_patch(border)


    # show
    fig.tight_layout()
    # 关闭坐标轴
    plt.axis('off')
    # 保存图片
    plt.savefig(r"C:\Users\fanqi\Documents\GitHub\AutoDNS\Image\实验二特征重要性图\\"+draw_description+'.png')
    # 增加标题
    plt.title(draw_description, fontdict={'size': 16})
    plt.show()


if __name__ == '__main__':
    feature_importance_path = r'C:\Users\fanqi\Documents\GitHub\AutoDNS\Code\AutoDNS\code\AutoML\FeatureImportance\lab2_feature_importance.csv'
    feature_importance = pd.read_csv(feature_importance_path, index_col=0, header=0)  # 从CSV文件加载数据并创建DataFrame对象
    print(feature_importance)

    # 0->ip 1->udp 2-dns
    flag = 2

    if flag == 0:
        for IP_Header_With_Feature in IP_Header_With_Features:
            raw = IP_Header_With_Feature.raw  # 所在行数
            col = IP_Header_With_Feature.col  # 所在列数
            bit = IP_Header_With_Feature.bit  # nprint占用的个数
            width = IP_Header_With_Feature.width  # 宽度
            description = IP_Header_With_Feature.description

            # 判断特征是否部分在特征列表中
            not_zero = False
            if bit == 1 and description in feature_importance.index:
                not_zero = True
            elif bit > 1:
                for b in range(bit):
                    if f'{description}_{b}' in feature_importance.index:
                        not_zero = True
                        break
            else:
                not_zero = False

            if not_zero:
                # 计算每个特征重要性的平均值
                weight_count = 0
                weight_total = 0
                for b in range(bit):
                    weight_count += 1
                    feature = f'{description}_{b}'
                    # 假设你的DataFrame对象名为df
                    if feature in feature_importance.index:
                        weight = feature_importance.at[feature, 'p_value']
                    else:
                        weight = 0
                    weight_total += weight
                IP_Header_With_Feature.weight = float(weight_total) / weight_count
                # if description == 'ip_len':
                print(f'{description}={IP_Header_With_Feature.weight}')
            else:
                print(f'{description}_0')
                IP_Header_With_Feature.weight = 0
        packet = Packet(5)
        data = draw_format(packet, IP_Header_With_Features)
        print(data)
        draw(data, IP_Header_With_Features,"IP Header")
    elif flag == 1:
        for UDP_Header_With_Feature in UDP_Header_With_Features:
            raw = UDP_Header_With_Feature.raw  # 所在行数
            col = UDP_Header_With_Feature.col  # 所在列数
            bit = UDP_Header_With_Feature.bit  # nprint占用的个数
            width = UDP_Header_With_Feature.width  # 宽度
            description = UDP_Header_With_Feature.description

            # 判断特征是否部分在特征列表中
            not_zero = False
            if bit == 1 and description in feature_importance.index:
                not_zero = True
            elif bit > 1:
                for b in range(bit):
                    if f'{description}_{b}' in feature_importance.index:
                        not_zero = True
                        break
            else:
                not_zero = False

            if not_zero:
                # 计算每个特征重要性的平均值
                weight_count = 0
                weight_total = 0
                for b in range(bit):
                    weight_count += 1
                    feature = f'udp_{description}_{b}'
                    # 假设你的DataFrame对象名为df
                    if feature in feature_importance.index:
                        weight = feature_importance.at[feature, 'p_value']
                    else:
                        weight = 0
                    weight_total += weight
                UDP_Header_With_Feature.weight = float(weight_total) / weight_count
            else:
                UDP_Header_With_Feature.weight = 0
        packet = Packet(2)
        data = draw_format(packet, UDP_Header_With_Features)
        print(data)
        draw(data, UDP_Header_With_Features,"UDP Header")
    elif flag == 2:
        for DNS_Header_With_Feature in DNS_Header_With_Features:
            raw = DNS_Header_With_Feature.raw  # 所在行数
            col = DNS_Header_With_Feature.col  # 所在列数
            bit = DNS_Header_With_Feature.bit  # nprint占用的个数
            width = DNS_Header_With_Feature.width  # 宽度
            description = DNS_Header_With_Feature.description

            not_zero = False
            if bit == 1 and description in feature_importance.index:
                not_zero = True
            elif bit > 1:
                for b in range(bit):
                    if f'{description}_{b}' in feature_importance.index:
                        not_zero = True
                        break
            else:
                not_zero = False

            if not_zero:
                # 计算每个特征重要性的平均值
                weight_count = 0
                weight_total = 0
                for b in range(bit):
                    weight_count += 1
                    feature = f'{description}_{b}'
                    # 假设你的DataFrame对象名为df
                    if feature in feature_importance.index:
                        weight = feature_importance.at[feature, 'p_value']
                    else:
                        weight = 0
                    weight_total += weight
                DNS_Header_With_Feature.weight = float(weight_total) / weight_count
            else:
                DNS_Header_With_Feature.weight = 0
        packet = Packet(5)
        data = draw_format(packet, DNS_Header_With_Features)
        print(data)
        draw(data, DNS_Header_With_Features,"DNS Header")
