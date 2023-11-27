#  Copyright (c) 2023. Lorem ipsum dolor sit amet, consectetur adipiscing elit.
#  Morbi non lorem porttitor neque feugiat blandit. Ut vitae ipsum eget quam lacinia accumsan.
#  Etiam sed turpis ac ipsum condimentum fringilla. Maecenas magna.
#  Proin dapibus sapien vel ante. Aliquam erat volutpat. Pellentesque sagittis ligula eget metus.
#  Vestibulum commodo. Ut rhoncus gravida arcu.

import os
import fnmatch
from collections import Counter
from itertools import islice
from random import random

from autogluon.core import TabularDataset
from autogluon.tabular import TabularPredictor
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
import pandas as pd
import csv
import random
import tempfile
import shutil


# 获取指定路径下的所有一级子目录名称
def get_subdirectories(path):
    subdirectories = [name for name in os.listdir(path) if os.path.isdir(os.path.join(path, name))]
    return subdirectories


# 遍历指定路径下及其子目录下的所有子目录名称
def get_all_subdirectories(path):
    subdirectories = get_subdirectories(path)
    for subdir in subdirectories:
        subdir_path = os.path.join(path, subdir)
        print(subdir_path)
        get_all_subdirectories(subdir_path)


def get_pcap_files(path):
    # 获取指定目录下所有文件
    files = os.listdir(path)
    # 初始化 PCAP 文件列表
    pcap_files = []
    # 遍历所有文件，找到以 ".pcap" 结尾的文件
    for file in files:
        if fnmatch.fnmatch(file, '*.pcap'):
            pcap_files.append(os.path.join(path, file))
    return pcap_files


def get_csv_files(path):
    # 获取指定目录下所有文件
    files = os.listdir(path)
    # 初始化 CSV 文件列表
    csv_files = []
    # 遍历所有文件，找到以 ".pcap" 结尾的文件
    for file in files:
        if fnmatch.fnmatch(file, '*.csv'):
            csv_files.append(os.path.join(path, file))
    return csv_files


# 对于很大的 CSV 文件，将整个文件读入内存并计算行数可能会导致内存不足的问题。因此，更好的方法是逐行读取文件并计数。
def get_csv_rows(filename):
    with open(filename, 'r', encoding='utf-8') as f:
        count = 0
        for line in f:
            count += 1
    return count


def shuffle_csv_file(csv_file_path, header=True):
    tmp_file = csv_file_path + '.tmp'
    with open(csv_file_path, 'rb') as f1, \
            open(tmp_file, 'wb') as f2:
        # 处理标题行
        if header:
            header_line = f1.readline()
            f2.write(header_line)
        # 按行打乱数据并写回新文件
        lines = f1.readlines()
        random.shuffle(lines)
        f2.writelines(lines)
    # 移除原文件并将新文件命名为原文件名
    os.remove(csv_file_path)
    os.rename(tmp_file, csv_file_path)


def shuffle_large_csv_file(csv_file_path, chunk_size=10000):
    output_file_path = csv_file_path + ".csv"
    # 创建临时文件夹用于存储排序后的块文件
    temp_dir = tempfile.mkdtemp()
    if not os.path.exists(temp_dir):
        try:
            os.makedirs(temp_dir)
            print(f"文件夹 '{temp_dir}' 创建成功！")
        except OSError as e:
            print(f"创建文件夹 '{temp_dir}' 失败：{e}")
    else:
        print(f"文件夹 '{temp_dir}' 已经存在。")
    # 分割原始文件为多个块文件并进行排序
    with open(csv_file_path, 'r') as input_file:
        reader = csv.reader(input_file)
        header = next(reader)  # 读取标题行
        current_chunk = 1
        chunk_rows = []
        for row in reader:
            chunk_rows.append(row)
            if len(chunk_rows) >= chunk_size:
                # 对当前块进行随机化排序
                random.shuffle(chunk_rows)
                # 将排序后的块写入临时文件
                chunk_file_path = temp_dir + os.sep + 'chunk_' + str(current_chunk) + '.csv'
                with open(chunk_file_path, 'w+', newline='') as chunk_file:
                    writer = csv.writer(chunk_file)
                    writer.writerow(header)
                    writer.writerows(chunk_rows)
                chunk_rows = []
                current_chunk += 1
        # 处理最后一个块
        if chunk_rows:
            random.shuffle(chunk_rows)
            chunk_file_path = temp_dir + os.sep + 'chunk_' + str(current_chunk) + '.csv'
            with open(chunk_file_path, 'w+', newline='') as chunk_file:
                writer = csv.writer(chunk_file)
                writer.writerow(header)
                writer.writerows(chunk_rows)
    # 合并排序后的块文件并进行打乱
    chunk_files = [(temp_dir + os.sep + 'chunk_' + str(i) + '.csv') for i in range(1, current_chunk + 1)]
    print(chunk_files)
    with open(output_file_path, 'w+', newline='') as output_file:
        writer = csv.writer(output_file)
        writer.writerow(header)
        for chunk_file in chunk_files:
            with open(chunk_file, 'r') as chunk:
                reader = csv.reader(chunk)
                next(reader)  # 跳过每个块的标题行
                for row in reader:
                    writer.writerow(row)
    # 删除临时文件夹
    shutil.rmtree(temp_dir)
    # 移除原文件并将新文件命名为原文件名
    os.remove(csv_file_path)
    os.rename(output_file_path, csv_file_path)


def merge_csv_files(folder_path, save_file_path, save_file_name=r'merge.csv'):
    save_name_with_path = save_file_path + os.path.sep + save_file_name
    if os.path.exists(save_name_with_path):
        os.remove(save_name_with_path)
    # 修改当前工作目录
    os.chdir(folder_path)
    # 将该文件夹下的所有文件名存入一个列表
    file_list = []
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            if file.endswith('.csv'):
                file_list.append(os.path.join(root, file))
    # 读取第一个CSV文件并包含表头
    chunks_first = pd.read_csv(file_list[0], encoding="utf-8", chunksize=102400)
    for chunk_first in chunks_first:
        chunk_first.to_csv(save_name_with_path, encoding="utf-8", index=False,
                           header=True,
                           mode='a+')
    # 循环遍历列表中各个CSV文件名，并追加到合并后的文件
    for i in range(1, len(file_list)):
        if file_list[i] == save_name_with_path:
            continue
        chunks = pd.read_csv(file_list[i], chunksize=102400)
        for chunk in chunks:
            chunk.to_csv(save_name_with_path, encoding="utf-8", index=False, header=False,
                         mode='a+')
    print("INFO::Merge folder \"" + folder_path + "\" to single .CSV file successfully.")
    return save_file_path + os.sep + save_file_name


def split_dataset(input_csv_path, output_train_path, output_val_path, train_ratio=0.8):
    """
    将一个CSV文件划分为训练集和验证集
    Args:
        input_csv_path: 要划分的CSV文件路径
        output_train_path: 训练集的输出路径
        output_val_path: 验证集的输出路径
        train_ratio: 训练集的比例，默认为0.8
    """
    # 读取CSV文件
    data = pd.read_csv(input_csv_path)

    # 随机打乱数据
    data = data.sample(frac=1).reset_index(drop=True)

    # 划分训练集和验证集
    train_size = int(train_ratio * len(data))
    train_data = data[:train_size]
    val_data = data[train_size:]

    # 保存训练集和验证集到CSV文件
    train_data.to_csv(output_train_path, index=False)
    val_data.to_csv(output_val_path, index=False)


def encode_csv_label(csv_file_path, save_path):
    # 读取CSV文件
    data = pd.read_csv(csv_file_path)
    # 创建LabelEncoder对象
    label_encoder = LabelEncoder()
    # 对label列进行编码
    data['label'] = label_encoder.fit_transform(data['label'])
    # 保存编码后的数据
    data.to_csv(save_path, index=False)


def get_csv_column_num(csv_file_path):
    # 获取CSV文件的大小
    file_size = os.path.getsize(csv_file_path)

    # 读取文件的第一行
    with open(csv_file_path, 'r') as f:
        reader = csv.reader(f)
        header = next(reader)

    # 获取列数
    column_num = len(header)

    # 如果文件大小超过1MB，则读取前10行进行计算
    if file_size > 1024 * 1024:
        data = pd.read_csv(csv_file_path, nrows=10)
        column_num = data.shape[1]

    return column_num


# 快速获取超大csv的最后一列的标签的类别的数量，注意内存限制
def get_label_class_num(csv_file_path, chunk_size=10000):
    label_class_num = {}
    header = pd.read_csv(csv_file_path, nrows=0).columns[-1]
    for chunk in pd.read_csv(csv_file_path, chunksize=chunk_size):
        labels = chunk[header].unique()
        for label in labels:
            if label not in label_class_num:
                label_class_num[label] = 0
            label_class_num[label] += len(chunk[chunk[header] == label])
    return label_class_num


def balanced_sampling_large_csv_file(input_csv_path, output_csv_path):
    """
    从给定的CSV文件进行抽样，确保得到的CSV中每个标签类别的样本数目相同
    Args:
        input_csv_path: 输入CSV文件路径
        output_csv_path: 输出CSV文件路径
    """
    # 统计每个标签类别的样本数目
    label_counts = Counter()

    # 统计每个标签类别的起始行索引
    label_start_indices = {}

    # 读取CSV文件，统计标签数目和起始行索引
    with open(input_csv_path, 'r', newline='') as file:
        reader = csv.reader(file)
        header = next(reader)  # 读取表头
        label_column = header[-1]  # 最后一列为标签列

        for i, row in enumerate(reader, start=2):  # 从第二行开始计数
            label = row[-1]  # 获取标签值
            label_counts[label] += 1

            if label not in label_start_indices:
                label_start_indices[label] = i

    # 计算每个类别的最小样本数
    min_count = min(label_counts.values())
    print(f'min_count:{min_count}')
    # 初始化抽样结果的CSV文件
    with open(output_csv_path, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(header)  # 写入表头

        # 对每个标签类别进行抽样
        for label, count in label_counts.items():
            # 获取当前类别的起始行索引
            start_index = label_start_indices[label]

            # 读取当前类别的样本行
            with open(input_csv_path, 'r', newline='') as file:
                reader = csv.reader(file)
                next(reader)  # 跳过表头

                # 定位到起始行索引
                for _ in range(start_index - 2):  # 从第二行开始计数
                    next(reader)

                # 随机抽样指定数量的样本行
                sampled_rows = []
                for _ in range(min_count):
                    sampled_rows.append(next(reader))

            # 将抽样的样本行写入结果CSV文件
            writer.writerows(sampled_rows)

def drop_duplicated():
    import pandas as pd

    # 读取 train.csv 和 val.csv 文件
    train_data = pd.read_csv(r'C:\Users\fanqi\Documents\GitHub\AutoDNS\Code\AutoDNS\code\AutoPrint\Dataset\DoHBrw-2020\train\train.csv')
    val_data = pd.read_csv(r'C:\Users\fanqi\Documents\GitHub\AutoDNS\Code\AutoDNS\code\AutoPrint\Dataset\DoHBrw-2020\val\val.csv')

    # 合并 train_data 和 val_data
    merged_data = pd.concat([train_data, val_data])

    # 去重
    deduplicated_data = merged_data.drop_duplicates()

    # 保存去重后的数据到 deduplicated.csv 文件
    deduplicated_data.to_csv('deduplicated.csv', index=False)

def get_csv_row_count(file_path, chunk_size=10000):
    total_rows = 0

    with open(file_path, 'r') as file:
        reader = csv.reader(file)
        header = next(reader)  # 如果有标题行，可以使用 next(reader) 跳过

        chunk = list(islice(reader, chunk_size))
        while chunk:
            total_rows += len(chunk)
            chunk = list(islice(reader, chunk_size))

    return total_rows

def count_label_occurrences(file_path, label, chunk_size=10000):
    count = 0

    with open(file_path, 'r') as file:
        reader = csv.reader(file)
        header = next(reader)  # 如果有标题行，可以使用 next(reader) 跳过

        chunk = list(islice(reader, chunk_size))
        while chunk:
            for row in chunk:
                if int(row[-1]) == int(label) or str(row[-1]) == str(label):
                    count += 1
            chunk = list(islice(reader, chunk_size))

    return count

def add_label_to_last_column(csv_file, label):
    # 读取CSV文件
    with open(csv_file, 'r') as file:
        reader = csv.reader(file)
        rows = list(reader)

    # 在最后一列的每一行添加标签
    for i, row in enumerate(rows):
        if i == 0:  # 判断是否为第一行
            row.append('label')
        else:
            row.append(label)
    # 写入更新后的CSV文件
    with open(csv_file, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerows(rows)


def remove_first_column(input_file, output_file):
    with open(input_file, 'r') as file_in, open(output_file, 'w', newline='') as file_out:
        reader = csv.reader(file_in)
        writer = csv.writer(file_out)

        for row in reader:
            # 切片操作去除第一列
            new_row = row[1:]
            writer.writerow(new_row)

if __name__ == '__main__':
    #print(count_label_occurrences(r'C:\Users\fanqi\Documents\GitHub\AutoDNS\Code\AutoDNS\code\AutoPrint\Dataset\DoHBrw-2020\train\train.csv')) #3278618
    #print(get_csv_row_count(r'C:\Users\fanqi\Documents\GitHub\AutoDNS\Code\AutoDNS\code\AutoPrint\Dataset\DoHBrw-2020\val\val.csv')) #819655

    #add_label_to_last_column(r"C:\Users\fanqi\Documents\GitHub\AndroPyTool\APK\SMSmalware.csv",'SMSmalware')
    #remove_first_column(r"C:\Users\fanqi\Documents\GitHub\AndroPyTool\APK\SMSmalware.csv",r"C:\Users\fanqi\Documents\GitHub\AndroPyTool\APK\SMSmalware_remove.csv")
    #merge_csv_files(r"C:\Users\fanqi\Documents\GitHub\AndroPyTool\APK\remove",r"C:\Users\fanqi\Documents\GitHub\AndroPyTool\APK\merge")
    #shuffle_csv_file(r"C:\Users\fanqi\Documents\GitHub\AndroPyTool\APK\merge\merge.csv")

    """
    train_data_path = r"C:\Users\fanqi\Documents\GitHub\AndroPyTool\APK\merge\merge.csv"
    #test_data_path = dataset_folder + r'\val\val.csv'
    dataset = TabularDataset(train_data_path)
    train_data, test_data = train_test_split(dataset, test_size=0.2, random_state=42)

    predictor = TabularPredictor(label='label').fit(train_data, time_limit=600, ag_args_fit={"ag.max_memory_usage_ratio": 6.00})

    leaderboard = predictor.leaderboard(test_data)
    print(leaderboard)
    leaderboard_df = pd.DataFrame(leaderboard)
    leaderboard_df.to_csv('leaderboard-apk.csv', index=False)
    """

    import seaborn as sns
    import pandas as pd
    from autogluon.tabular import TabularDataset, TabularPredictor
    import torch
    import matplotlib.pyplot as plt
    import seaborn as sns
    from sklearn.metrics import confusion_matrix, roc_curve, auc
    from sklearn.model_selection import train_test_split
    import random

    # 使用 Matplotlib 绘制混淆矩阵
    plt.figure(figsize=(10, 8),dpi=1200)
    class_names = ['Benign', 'Dns2tcp', 'Dnscat2', 'Iodine']
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',xticklabels=class_names, yticklabels=class_names, annot_kws={'size': 12})
    plt.xlabel('Predicted Label', labelpad=10)
    plt.ylabel('True Label', labelpad=10)
    #plt.title('Confusion Matrix')
    # 将 x 轴标签文字旋转为斜体
    #plt.xticks(rotation=45)  # 调整旋转角度
    plt.savefig(r"C:\Users\fanqi\Documents\GitHub\AutoDNS\Image\实验三特征重要性图\matrix_fanqin_4.png")
    plt.show()
