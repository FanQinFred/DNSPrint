#  Copyright (c) 2023. Lorem ipsum dolor sit amet, consectetur adipiscing elit.
#  Morbi non lorem porttitor neque feugiat blandit. Ut vitae ipsum eget quam lacinia accumsan.
#  Etiam sed turpis ac ipsum condimentum fringilla. Maecenas magna.
#  Proin dapibus sapien vel ante. Aliquam erat volutpat. Pellentesque sagittis ligula eget metus.
#  Vestibulum commodo. Ut rhoncus gravida arcu.

import numpy as np
import pandas as pd
import torch
from torch import nn
from torch.utils.data import Dataset, DataLoader


class CSVLoader(Dataset):
    def __init__(self, filepath, transform=None):
        self.data = pd.read_csv(filepath)  # 加载CSV文件
        self.transform = transform

    def __len__(self):
        return len(self.data)

    def __getitem__(self, idx):
        if torch.is_tensor(idx):
            idx = idx.tolist()

        features = self.data.iloc[idx, :-1].values.astype(np.float64)  # 获取输入特征列
        target = self.data.iloc[idx, -1:].values.astype(np.int64)  # 获取目标列

        if self.transform:
            features = self.transform(features)

        return features, target


class RNNNet(nn.Module):
    def __init__(self, input_size, class_num):

        self.input_size = input_size
        self.class_num = class_num
        super(RNNNet, self).__init__()

        self.lstm1 = nn.LSTM(input_size=input_size, hidden_size=1024, batch_first=True)
        self.drop1 = nn.Dropout(0.5)

        self.lstm2 = nn.LSTM(input_size=1024, hidden_size=1024, batch_first=True)
        self.drop2 = nn.Dropout(0.5)

        self.lstm3 = nn.LSTM(input_size=1024, hidden_size=1024, batch_first=True)
        self.drop3 = nn.Dropout(0.5)

        self.lstm4 = nn.LSTM(input_size=1024, hidden_size=1024, batch_first=True)
        self.drop4 = nn.Dropout(0.5)

        self.lstm5 = nn.LSTM(input_size=1024, hidden_size=1024, batch_first=True)
        self.drop5 = nn.Dropout(0.5)

        self.lstm6 = nn.LSTM(input_size=1024, hidden_size=1024, batch_first=True)
        self.drop6 = nn.Dropout(0.5)

        self.lstm7 = nn.LSTM(input_size=1024, hidden_size=1024, batch_first=True)
        self.drop7 = nn.Dropout(0.5)

        self.lstm8 = nn.LSTM(input_size=1024, hidden_size=1024, batch_first=True)
        self.drop8 = nn.Dropout(0.5)

        self.lstm9 = nn.LSTM(input_size=1024, hidden_size=1024, batch_first=True)
        self.drop9 = nn.Dropout(0.5)

        self.lstm10 = nn.LSTM(input_size=1024, hidden_size=1024, batch_first=True)
        self.drop10 = nn.Dropout(0.5)

        self.fc = nn.Linear(1024, self.class_num)
        self.float()  # 将输入数据类型定义为float

    def forward(self, x):
        x = x.view(-1, 1, self.input_size)

        out, _ = self.lstm1(x)
        out = self.drop1(nn.functional.relu(out))

        out, _ = self.lstm2(out)
        out = self.drop2(nn.functional.relu(out))

        out, _ = self.lstm3(out)
        out = self.drop3(nn.functional.relu(out))

        out, _ = self.lstm4(out)
        out = self.drop4(nn.functional.relu(out))

        out, _ = self.lstm5(out)
        out = self.drop5(nn.functional.relu(out))

        out, _ = self.lstm6(out)
        out = self.drop6(nn.functional.relu(out))

        out, _ = self.lstm7(out)
        out = self.drop7(nn.functional.relu(out))

        out, _ = self.lstm8(out)
        out = self.drop8(nn.functional.relu(out))

        out, _ = self.lstm9(out)
        out = self.drop9(nn.functional.relu(out))

        out, (hidden, _) = self.lstm10(out)
        out = self.drop10(nn.functional.relu(hidden[-1]))
        out = self.fc(out)
        return out

class RNNNetMini(nn.Module):
    def __init__(self,input_size,class_num):
        self.input_size = input_size
        self.class_num = class_num
        super(RNNNetMini, self).__init__()
        self.lstm1 = nn.LSTM(input_size=input_size, hidden_size=256, batch_first=True)
        self.drop1 = nn.Dropout(0.5)
        self.lstm2 = nn.LSTM(input_size=256, hidden_size=256, batch_first=True)
        self.drop2 = nn.Dropout(0.5)
        self.lstm3 = nn.LSTM(input_size=256, hidden_size=256, batch_first=True)
        self.drop3 = nn.Dropout(0.5)
        self.lstm4 = nn.LSTM(input_size=256, hidden_size=256, batch_first=True)
        self.drop4 = nn.Dropout(0.5)
        self.fc = nn.Linear(256, self.class_num)
        self.float()  # 将输入数据类型定义为float

    def forward(self, x):
        x = x.view(-1, 1, self.input_size)
        out, _ = self.lstm1(x)
        out = self.drop1(nn.functional.relu(out))
        out, _ = self.lstm2(out)
        out = self.drop2(nn.functional.relu(out))
        out, _ = self.lstm3(out)
        out = self.drop3(nn.functional.relu(out))
        out, (hidden, _) = self.lstm4(out)
        out = self.drop4(nn.functional.relu(hidden[-1]))
        out = self.fc(out)
        return out