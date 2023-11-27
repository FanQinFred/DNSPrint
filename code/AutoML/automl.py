import pandas as pd
from autogluon.tabular import TabularDataset, TabularPredictor
import torch
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import confusion_matrix, roc_curve, auc
from sklearn.model_selection import train_test_split
import random
def train():
    train_data_path = dataset_folder + r'\val\val.csv'
    #test_data_path = dataset_folder + r'\val\val.csv'

    dataset = TabularDataset(train_data_path)
    #test_data = TabularDataset(test_data_path)

    # 指定采样数量
    #sample_count = 10000
    # 随机采样指定数量的样本
    #train_data = train_data.sample(n=sample_count, random_state=42)

    # 加载数据集
    #dataset = TabularDataset('data.csv')

    # 划分训练集和测试集
    train_data, test_data = train_test_split(dataset, test_size=0.99, random_state=42)

    predictor = TabularPredictor(label='label').fit(train_data, time_limit=600, ag_args_fit={"ag.daosh": 6.00})

    leaderboard = predictor.leaderboard(test_data)
    print(leaderboard)
    leaderboard_df = pd.DataFrame(leaderboard)
    leaderboard_df.to_csv('leaderboard-doh-99.csv', index=False)


def balance_csv_dataset(df):
    # 读取 CSV 文件
    # 获取标签列名称
    label_column = df.columns[-1]

    # 计算每个类别的样本数量
    class_counts = df[label_column].value_counts()
    min_count = class_counts.min()

    # 平衡数据集
    balanced_data = pd.DataFrame()
    for label in class_counts.index:
        # 获取当前类别的样本
        samples = df[df[label_column] == label].sample(n=min_count, random_state=42)

        # 将样本添加到平衡数据集中
        balanced_data = balanced_data.append(samples)

    # 重新排序数据集
    balanced_data = balanced_data.reset_index(drop=True)

    return balanced_data

def validate(model_path):
    val_data_path = dataset_folder + r'\train\train.csv'

    val_data = TabularDataset(val_data_path)
    val_data = balance_csv_dataset(val_data)
    y_test = val_data["label"]  # values to predict
    test_data_nolab = val_data.drop(columns=["label"])  # delete label column to prove we're not cheating
    test_data_nolab.head()

    predictor = TabularPredictor.load(
        model_path)  # unnecessary, just demonstrates how to load previously-trained predictor from file


    y_pred = predictor.predict(test_data_nolab,model="RandomForestEntr")
    print("Predictions:  \n", y_pred)
    perf = predictor.evaluate_predictions(y_true=y_test, y_pred=y_pred, auxiliary_metrics=True)
    print(perf)

    pred_probs = predictor.predict_proba(test_data_nolab,model="RandomForestEntr")
    print(pred_probs.head(5))

    # 计算混淆矩阵
    cm = confusion_matrix(y_test, y_pred)

    import seaborn as sns

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

    leaderboard = predictor.leaderboard(val_data)
    print(leaderboard)



    # 进行预测并获取预测概率
    y_pred_proba = predictor.predict_proba(val_data,model="RandomForestEntr")
    # 获取正类别的预测概率（通常是第一个类别）
    # y_scores = y_pred_proba.iloc[:, 1]
    # 获取真实标签
    y_true = val_data['label']


    # 假设y_scores是每个类别的预测概率矩阵，每一列代表一个类别的概率
    # 假设y_true是真实的类别标签
    # 假设有n个类别
    n = 4
    # 绘制每个类别的ROC曲线
    for i in range(n):
        # 将当前类别设为正例，其他类别设为负例
        y_true_binary = (y_true == i)
        y_scores_binary = y_pred_proba.iloc[:, i]

        # 计算当前类别的假正率、真正率和阈值
        fpr, tpr, thresholds = roc_curve(y_true_binary, y_scores_binary)

        # 计算当前类别的AUC
        roc_auc = auc(fpr, tpr)

        # 绘制ROC曲线
        plt.plot(fpr, tpr, label='Class {0} (AUC = {1:.2f})'.format(class_names[i], roc_auc))
    #plt.figure(figsize=(10, 8), dpi=1200)
    # 设置图例、坐标轴标签和标题
    plt.legend()
    plt.xlabel('Precision')
    plt.ylabel('Recall')
    plt.title('Receiver Operating Characteristic Curve')
    plt.savefig(r"C:\Users\fanqi\Documents\GitHub\AutoDNS\Image\实验三特征重要性图\roc_fanqin_4.png")
    # 显示图形
    plt.show()


    #feature_importance = predictor.feature_importance(data=val_data)
    #print(feature_importance)
    # 假设你的DataFrame对象名为df
    #feature_importance.to_csv('FeatureImportance/doh_feature_importance.csv')  # 保存为CSV文件，不包含索引


if __name__ == '__main__':
    print(f'CUDA IS Available: {torch.cuda.is_available()}')
    print(f'CUDA Count: {torch.cuda.device_count()}')
    # 数据集文件夹
    dataset_folder = r"C:\Users\fanqi\Documents\GitHub\AutoDNS\Code\AutoDNS\code\AutoPrint\Dataset\DoHBrw-2020"
    # 模型路径
    model_path = r"C:\Users\fanqi\Documents\GitHub\AutoDNS\Code\AutoDNS\code\AutoML\AutogluonModels\99"

    flag = 1

    if flag == 0:
        train()
    elif flag == 1:
        validate(model_path)
    else:
        pass
