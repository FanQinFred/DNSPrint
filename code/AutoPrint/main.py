#  Copyright (c) 2023. Lorem ipsum dolor sit amet, consectetur adipiscing elit.
#  Morbi non lorem porttitor neque feugiat blandit. Ut vitae ipsum eget quam lacinia accumsan.
#  Etiam sed turpis ac ipsum condimentum fringilla. Maecenas magna.
#  Proin dapibus sapien vel ante. Aliquam erat volutpat. Pellentesque sagittis ligula eget metus.
#  Vestibulum commodo. Ut rhoncus gravida arcu.

import multiprocessing
import os
import shutil
import seaborn as sns
import torch
from matplotlib import pyplot as plt
from sklearn.metrics import confusion_matrix
from torch import nn
from torch.utils.data import DataLoader
from Model.RNNNet import RNNNet, CSVLoader
from Utils.FileUtil import get_subdirectories, get_pcap_files, get_csv_files, get_csv_rows, merge_csv_files, \
    split_dataset, get_csv_column_num, get_label_class_num, shuffle_large_csv_file
from Utils.DNSPrintUtil import process_pcap_file_to_csv


def encode_pcap_folder(raw_foler, packet_max_count=-1,device='cpu'):
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
            pool.apply_async(process_pcap_file_to_csv, (pcap_file, csv_file, value_label, packet_max_count, device))
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
    split_dataset(merge_csv_path, output_train_path, output_val_path, 0.8)

    print(temp_merge_csv_dir)
    if os.path.exists(temp_merge_csv_dir):
        shutil.rmtree(temp_merge_csv_dir)
    print("INFO::Generate dataset successfully.")


def train(train_file_path, epochs):
    use_cuda = True
    device = torch.device("cuda" if (use_cuda and torch.cuda.is_available()) else "cpu")
    print("Current Device: " + str(device))

    dataset = CSVLoader(train_file_path)
    dataloader = DataLoader(dataset, batch_size=1024, num_workers=2, shuffle=True, drop_last=True)

    input_size = get_csv_column_num(train_file_path) - 1
    class_num = get_label_class_num(train_file_path)
    print("INFO::Training Class Dict is " + str(class_num))
    total_count = sum(class_num.values())
    print("INFO::Training Sample Total Count is " + str(total_count))

    # 初始化模型、优化器、损失函数
    model = RNNNet(input_size=input_size, class_num=len(class_num)).to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=0.0001)
    criterion = nn.CrossEntropyLoss()

    # Loss
    pre_loss = 0
    curr_loss = 0

    # 画图专用
    loss_y = []
    acc_y = []

    # 训练
    for epoch in range(epochs):  # 可根据情况改变epoch数
        # 记录先前的loss
        pre_loss = curr_loss
        # 当前loss累计
        running_loss = 0.0
        # 正确样本数量
        correct = 0
        # 样本总数量
        total = 0
        for i, data in enumerate(dataloader, 0):
            inputs, labels = data

            inputs, labels = inputs.double(), labels.long()  # 注意转换数据类型
            labels = labels[:, 0]  # 提取第一列，只保留二元分类标签

            inputs = torch.Tensor(inputs)
            labels = torch.Tensor(labels)

            inputs = inputs.to(device)
            labels = labels.to(device)

            optimizer.zero_grad()
            outputs = model(inputs.float())

            loss = criterion(outputs, labels)
            loss.backward()
            optimizer.step()
            running_loss += loss.item()
            _, predicted = torch.max(outputs.data, 1)
            total += labels.size(0)
            correct += (predicted == labels).sum().item()
        curr_loss = running_loss / len(dataloader)

        # 记录loss和acc绘图
        loss_y.append(curr_loss)
        acc_y.append(100 * correct / total)

        # 打印
        print('epoch:%d loss: %.3f, Acc:%.3f' % (epoch + 1, running_loss / len(dataloader), 100 * correct / total))
        # 在每个epoch结束时保存模型
        if (epoch + 1) % 10 == 0 or (epoch + 1) == epochs:
            torch.save(model.state_dict(), f'epoch_{epoch + 1}.pt')

    # 绘制曲线
    fig, ax1 = plt.subplots()
    ax1.plot(loss_y, '-b', label='Training Loss')
    ax1.set_xlabel('Epoch')
    ax1.set_ylabel('Training Loss', color='b')
    ax1.tick_params('y', colors='b')

    # 添加第二条y轴，用于绘制accuracy曲线
    ax2 = ax1.twinx()
    ax2.plot(acc_y, '-r', label='Training Accuracy')
    ax2.set_ylabel('Training Accuracy', color='r')
    ax2.tick_params('y', colors='r')

    # 输出图例
    plt.legend(loc='upper right')

    # 显示图像
    plt.title('Training Loss and Accuracy')
    plt.show()

    # Finished Training
    print('Finished Training')
    return f'epoch_{epoch + 1}.pt'


def validate(val_file_path, model_save_path):
    use_cuda = True
    device = torch.device("cuda" if (use_cuda and torch.cuda.is_available()) else "cpu")
    print("Current Device: " + str(device))

    dataset = CSVLoader(val_file_path)
    dataloader = DataLoader(dataset, batch_size=1024, num_workers=2, shuffle=True, drop_last=True)

    input_size = get_csv_column_num(val_file_path) - 1
    class_num = get_label_class_num(val_file_path)
    print("INFO::Validating Class Dict is " + str(class_num))
    total_count = sum(class_num.values())
    print("INFO::Validating Sample Total Count is " + str(total_count))
    # 用于计算混淆矩阵
    labels_sorted_list = sorted(list(class_num.keys()))

    # 初始化混淆矩阵
    confusion_matrix_val = torch.zeros(len(class_num), len(class_num))

    # 初始化模型、优化器、损失函数
    model = RNNNet(input_size=input_size, class_num=len(class_num)).to(device)
    model.load_state_dict(torch.load(model_save_path))
    optimizer = torch.optim.Adam(model.parameters(), lr=0.0001)
    criterion = nn.CrossEntropyLoss()
    model.eval()
    # 当前loss累计
    running_loss = 0.0
    # 正确样本数量
    correct = 0
    # 样本总数量
    total = 0
    for i, data in enumerate(dataloader, 0):
        inputs, labels = data

        inputs, labels = inputs.double(), labels.long()  # 注意转换数据类型
        labels = labels[:, 0]  # 提取第一列，只保留二元分类标签

        inputs = torch.Tensor(inputs)
        labels = torch.Tensor(labels)

        inputs = inputs.to(device)
        labels = labels.to(device)

        optimizer.zero_grad()
        outputs = model(inputs.float())
        loss = criterion(outputs, labels)

        running_loss += loss.item()
        _, predicted = torch.max(outputs.data, 1)
        total += labels.size(0)
        correct += (predicted == labels).sum().item()

        # 计算批处理的混淆矩阵
        batch_confusion_matrix = confusion_matrix(labels.cpu().numpy(), predicted.cpu().numpy(),
                                                  labels=labels_sorted_list)
        confusion_matrix_val += batch_confusion_matrix

    # 打印
    print('loss: %.3f, Acc:%.3f' % (running_loss / len(dataloader), 100 * correct / total))
    # print('Validation Confusion Matrix:')
    # print(confusion_matrix_val)

    # 将混淆矩阵可视化
    fig, ax = plt.subplots(figsize=(8, 6))
    sns.heatmap(confusion_matrix_val, annot=True, fmt='.0f', cmap='Blues', xticklabels=labels_sorted_list,
                yticklabels=labels_sorted_list, ax=ax)
    plt.xlabel('Predicted Label')
    plt.ylabel('True Label')
    plt.show()

def check_device():
    use_cuda = True
    device = torch.device("cuda" if (use_cuda and torch.cuda.is_available()) else "cpu")
    print("Current Device: " + str(device))
    return device

# Press the green button in the gutter to run the script.
if __name__ == '__main__':

    # 数据集文件夹
    dataset_folder = r"C:\Users\fanqi\Documents\GitHub\AutoDNS\Code\AutoDNS\code\AutoPrint\Dataset\CICBellDNSFanQin"
    # 原始数据集文件啊及
    raw_foler = r"C:\Users\fanqi\Documents\GitHub\AutoDNS\Code\AutoDNS\data\CICBellDNS2021\Raw"

    # 模型文件
    model_save_path = r"C:\Users\fanqin\Documents\ExternalProject\VPNTorDetection\epoch_20.pt"


    # 训练数据集文件夹
    train_foler = dataset_folder + os.sep + "train"
    # 验证数据集文件夹
    val_foler = dataset_folder + os.sep + "val"
    label_dict = {}
    device = check_device()
    train_file_path = dataset_folder + r'\train\train.csv'
    val_file_path = dataset_folder + r'\val\val.csv'
    # 提取PCAP数据包的时候，从单个PCAP文件提取的最大包数，设置为-1的时候不限制
    packet_max_count = 50000
    epochs = 20

    # 阶段表示 0->数据处理 1->模型训练和验证 2->直接进行模型验证
    phase = 0

    if phase == 0 or '0' in str(phase):
        raw_foler = encode_pcap_folder(raw_foler, packet_max_count,device)
        generate_train_val_data(raw_foler,train_ratio=0.2)
        print(label_dict)
    elif phase == 1 or '1' in str(phase):
        model_save_path = train(train_file_path, epochs)
        validate(val_file_path, model_save_path)
    elif phase == 2 or '2' in str(phase):
        validate(val_file_path, model_save_path)
    else:
        print("INFO::No Operation.")
