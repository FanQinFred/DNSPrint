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

TCP_Header_With_Features = [Feature(0, 0, 16, 16, 4, "sport","Source Port Address"),
                            Feature(0, 16, 16, 16, 4, "dport","Destination Port Address"),
                            Feature(1, 0, 32, 32, 16, "seq","Sequence Number"),
                            Feature(2, 0, 32, 32, 32, "ack","Acknowledgement Number"),
                            Feature(3, 0, 4, 4, 4, "dataofs", "HLEN"),
                            Feature(3, 4, 6, 6, 6, "reserved", "Reserved"),

                            Feature(3, 10, 1, 1, 1, "flags_0", "U"),
                            Feature(3, 11, 1, 1, 1, "flags_1", "A"),
                            Feature(3, 12, 1, 1, 1, "flags_2", "P"),
                            Feature(3, 13, 1, 1, 1, "flags_3", "R"),
                            Feature(3, 14, 1, 1, 1, "flags_4", "S"),
                            Feature(3, 15, 1, 1, 1, "flags_5", "F"),

                            Feature(3, 16, 16, 16, 4, "window", "Window Size"),

                            Feature(4, 0, 16, 16, 4, "chksum", "Checksum"),
                            Feature(4, 16, 16, 16, 4, "urgptr", "Urgent Pointer"),

                            ]

TLS_Header_With_Features = [Feature(0, 0, 8, 8, 8, "type","Content Type "),
                            Feature(0, 8, 16, 16, 1, "version","Version "),
                            Feature(0, 24, 8, 8, 4, "len","Length "),
                            Feature(1, 0, 8, 8, 4, "len","Length "),]


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
        if width <= 32 and ((col + width-1)<32):
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
    plt.colorbar(im, shrink=0.8,location="top")  # 调整shrink的值来改变刻度条的大小

    # 填充数字
    for feature in feature_list:
        raw = feature.raw
        col = feature.col
        width = feature.width
        weight = feature.weight
        description = feature.description
        paint_description = feature.paint_description
        print('data[{},{}]:{} weight:{}'.format(raw, float(col +( float(width) / 2))-0.5, paint_description,weight))
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
    plt.savefig(r"C:\Users\fanqi\Documents\GitHub\AutoDNS\Image\实验三特征重要性图\\"+draw_description+'.png')

    # 增加标题
    plt.title(draw_description, fontdict={'size': 16})

    plt.show()



if __name__ == '__main__':
    feature_importance_path = r'C:\Users\fanqi\Documents\GitHub\AutoDNS\Code\AutoDNS\code\AutoML\FeatureImportance\doh_feature_importance.csv'
    feature_importance = pd.read_csv(feature_importance_path, index_col=0, header=0)  # 从CSV文件加载数据并创建DataFrame对象
    print(feature_importance)

    # 0->ip 1->tcp 2->tls
    flag = 1

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
        for TCP_Header_With_Feature in TCP_Header_With_Features:
            raw = TCP_Header_With_Feature.raw  # 所在行数
            col = TCP_Header_With_Feature.col  # 所在列数
            bit = TCP_Header_With_Feature.bit  # nprint占用的个数
            width = TCP_Header_With_Feature.width  # 宽度
            description = TCP_Header_With_Feature.description

            # 判断特征是否部分在特征列表中
            not_zero = False
            if bit == 1 and description in feature_importance.index:
                not_zero = True
            elif bit > 1:
                for b in range(bit):
                    if f'tcp_{description}_{b}' in feature_importance.index:
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
                    feature = f'tcp_{description}_{b}'
                    # 假设你的DataFrame对象名为df
                    if feature in feature_importance.index:
                        weight = feature_importance.at[feature, 'p_value']
                    else:
                        weight = 0
                    weight_total += weight
                TCP_Header_With_Feature.weight = float(weight_total) / weight_count
            else:
                TCP_Header_With_Feature.weight = 0
        packet = Packet(5)
        data = draw_format(packet, TCP_Header_With_Features)
        print(data)
        draw(data, TCP_Header_With_Features,"TCP Header")
    elif flag == 2:
        for TLS_Header_With_Feature in TLS_Header_With_Features:
            raw = TLS_Header_With_Feature.raw  # 所在行数
            col = TLS_Header_With_Feature.col  # 所在列数
            bit = TLS_Header_With_Feature.bit  # nprint占用的个数
            width = TLS_Header_With_Feature.width  # 宽度
            description = TLS_Header_With_Feature.description

            not_zero = False
            if bit == 1 and description in feature_importance.index:
                not_zero = True
            elif bit > 1:
                for b in range(bit):
                    if f'tls_{description}_{b}' in feature_importance.index:
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
                    feature = f'tls_{description}_{b}'
                    # 假设你的DataFrame对象名为df
                    if feature in feature_importance.index:
                        weight = feature_importance.at[feature, 'p_value']
                    else:
                        weight = 0
                    weight_total += weight
                TLS_Header_With_Feature.weight = float(weight_total) / weight_count
            else:
                TLS_Header_With_Feature.weight = 0
        packet = Packet(2)
        data = draw_format(packet, TLS_Header_With_Features)
        print(data)
        draw(data, TLS_Header_With_Features,"TLS Header")
