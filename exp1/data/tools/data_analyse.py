import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import classification_report
from sklearn.metrics import precision_recall_curve
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import make_scorer, f1_score
from sklearn.model_selection import GridSearchCV
import xgboost as xgb
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler

def train_data(row_data):
    global original_feature_names, pca, scaler
    original_feature_names = row_data.drop(['Label', 'Timestamp'], axis=1).columns.tolist()

    # 假设df已经经过清洗和编码
    # 1. 准备数据
    y = row_data['Label']
    X = row_data.drop(['Label', 'Timestamp'], axis=1) \
        [[ \
          # 'Fwd IAT Total',
          'Bwd Packet Length Max',
          'Destination Port',
          'Fwd Packet Length Max',
          # 'Bwd IAT Max',
          # 'Bwd IAT Total',
          'Total Length of Fwd Packets',
          'Bwd Packet Length Min',
          ]]
       #  [['Flow Byts/s', 'Dst Port', 'Flow IAT Max', 'Flow Duration',
       # 'Fwd Pkts/s', 'Init Fwd Win Byts', 'Flow Pkts/s', 'Flow IAT Mean',
       # 'Flow IAT Min', 'Bwd Pkts/s', 'Fwd IAT Max']] # 假设Timestamp还在
    print("Data types of features:\n", X.dtypes)
    print("Max values per column:\n", X.max())
    # print("Any inf in X:", np.isinf(X).values.any())

    le = LabelEncoder()
    y = le.fit_transform(y)
    # One-hot encode Protocol if you choose to
    # X = pd.get_dummies(X, columns=['Protocol'], prefix='Proto')

    # 2. 训练初始模型
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.4, random_state=42)
    # rf_initial = RandomForestClassifier(n_estimators=8, max_depth=8, random_state=42, n_jobs=-1,
    #                                     class_weight={0: 1, 1: 5})
    # rf_initial.fit(X_train, y_train)
    # sklearn_y_predict = rf_initial.predict(X_train)
    #
    # result = classification_report(y_train, sklearn_y_predict, digits=4, target_names=le.classes_)
    # print('\n', result)
    # 1. 对你的训练数据进行标准化
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)  # 使用训练集的scaler

    # 2. 应用PCA
    # 选择一个能保留例如95%方差的组件数，或者直接指定一个数量，比如24
    pca = PCA(n_components=0.95)  # 或者 pca = PCA(n_components=24)
    X_train_pca = pca.fit_transform(X_train_scaled)
    X_test_pca = pca.transform(X_test_scaled)

    gridSearchRaw(X_train, y_train, X_test, y_test, le)
    # gridSearch(X_train_pca, y_train, X_test_pca, y_test, le)
    # gridSearch_xgboost(X_train, y_train, X_test, y_test, le)
    # gridSearch_xgboost(X_train_pca, y_train, X_test_pca, y_test, le)
    # # 5. 使用筛选出的特征重新训练
    # X_train_selected = X_train[top_features]
    # X_test_selected = X_test[top_features]
    #
    # rf_final = RandomForestClassifier(n_estimators=8, max_depth=8, max_leaf_nodes=1000, random_state=42, n_jobs=-1,
    #                                   class_weight='balanced')
    # rf_final.fit(X_train_selected, y_train)


def gridSearchRaw(x_data, y_data, test_x, test_y, le):
    # ---------start
    # 1. 定义你要搜索的参数范围
    print('------------------测试开始--------------------')
    param_grid = {
        # 'n_estimators': [100],  # 树的数量
        'n_estimators': [ 3, 4 ],  # 树的数量
        'max_depth': [ 3, 4 ],  # 树的最大深度
        # 'max_depth': [4, 10, 15],  # 树的最大深度
        'max_leaf_nodes': [ 500, 1000, 1500 ],  # 最大叶子节点数
    }

    # 2. 创建一个普通的随机森林分类器
    rf = RandomForestClassifier(random_state=42)

    # 3. 定义我们的评估指标：我们关心的是DDoS类（假设标签为1）的F1分数
    #    或者使用 'f1_macro' 来兼顾两个类别
    # f1_scorer = make_scorer(f1_score, pos_label=1)
    f1_scorer = make_scorer(f1_score, average='macro')

    # 4. 创建GridSearchCV对象
    grid_search = GridSearchCV(
        estimator=rf,
        param_grid=param_grid,
        scoring=f1_scorer,  # 关键：告诉GridSearch我们的优化目标！
        cv=3,  # 3折交叉验证
        verbose=2,  # 打印搜索过程
        n_jobs=-1  # 使用所有CPU核心
    )

    # 5. 在训练数据上执行搜索
    grid_search.fit(x_data, y_data)

    # 6. 查看最佳参数和最佳模型
    print("最佳参数:", grid_search.best_params_)
    best_rf = grid_search.best_estimator_

    # 7. 使用这个最佳模型进行预测和评估
    y_pred = best_rf.predict(test_x)
    print(classification_report(test_y, y_pred))
    print('------------------测试完毕--------------------')

    # 精度召回率、阈值图
    y_pred_proba = best_rf.predict_proba(test_x)[:, 1]  # 获取DDoS类的预测概率
    precisions, recalls, thresholds = precision_recall_curve(test_y, y_pred_proba)
    plt.figure(figsize=(8, 6))
    plt.plot(thresholds, precisions[:-1], "b--", label="Precision")
    plt.plot(thresholds, recalls[:-1], "g-", label="Recall")
    plt.xlabel("Threshold")
    plt.legend(loc="center left")
    plt.ylim([0, 1])
    plt.title("Precision-Recall vs Threshold <Best Choice>")
    plt.grid(True)
    plt.savefig('precision_recall_threshold.svg', dpi=1200, bbox_inches='tight')
    plt.show()

    # 获取并显示特征重要性
    feature_names = x_data.columns
    importances = best_rf.feature_importances_
    importance_series = pd.Series(importances, index=feature_names).sort_values(ascending=False)

    print("Top 20 Features:")
    print(importance_series.head(20))

    # 可视化
    plt.figure(figsize=(12, 8))
    sns.barplot(x=importance_series.head(20).values, y=importance_series.head(20).index)
    plt.title('Feature Importances Raw')
    plt.xlabel('Importance')
    plt.ylabel('Features')
    plt.tight_layout()
    plt.savefig('mapped_feature_importances.svg', dpi=1200, bbox_inches='tight')
    plt.show()

    # 调整阈值的结果
    with open('precision_recall_threshold.txt', 'w') as out:
        out.write(f"最佳参数: {grid_search.best_params_}\n")
        out.write("\nTop 20 Features (Mapped from PCA):\n")
        out.write(importance_series.head(20).to_string())
        out.write("\n\n")
        for threshold in np.arange(0.1, 0.9, 0.05):
            y_pred_custom = (y_pred_proba >= threshold).astype(int)
            print(classification_report(test_y, y_pred_custom, digits=4, target_names=le.classes_))
            out.write(f"Threshold: {threshold:.2f}\n")
            out.write(classification_report(test_y, y_pred_custom, digits=4, target_names=le.classes_))

    return best_rf

def gridSearch(x_data, y_data, test_x, test_y, le):
    # ---------start
    # 1. 定义你要搜索的参数范围
    print('------------------测试开始--------------------')
    param_grid = {
        # 'n_estimators': [100],  # 树的数量
        'n_estimators': [ 3, 4 ],  # 树的数量
        'max_depth': [ 3, 4 ],  # 树的最大深度
        # 'max_depth': [4, 10, 15],  # 树的最大深度
        'max_leaf_nodes': [ 500, 1000, 1500 ],  # 最大叶子节点数
    }

    # 2. 创建一个普通的随机森林分类器
    rf = RandomForestClassifier(random_state=42)

    # 3. 定义我们的评估指标：我们关心的是DDoS类（假设标签为1）的F1分数
    #    或者使用 'f1_macro' 来兼顾两个类别
    # f1_scorer = make_scorer(f1_score, pos_label=1)
    f1_scorer = make_scorer(f1_score, average='macro')

    # 4. 创建GridSearchCV对象
    grid_search = GridSearchCV(
        estimator=rf,
        param_grid=param_grid,
        scoring=f1_scorer,  # 关键：告诉GridSearch我们的优化目标！
        cv=3,  # 3折交叉验证
        verbose=2,  # 打印搜索过程
        n_jobs=-1  # 使用所有CPU核心
    )

    # 5. 在训练数据上执行搜索
    grid_search.fit(x_data, y_data)

    # 6. 查看最佳参数和最佳模型
    print("最佳参数:", grid_search.best_params_)
    best_rf = grid_search.best_estimator_

    # 7. 使用这个最佳模型进行预测和评估
    y_pred = best_rf.predict(test_x)
    print(classification_report(test_y, y_pred))
    print('------------------测试完毕--------------------')

    # 精度召回率、阈值图
    y_pred_proba = best_rf.predict_proba(test_x)[:, 1]  # 获取DDoS类的预测概率
    precisions, recalls, thresholds = precision_recall_curve(test_y, y_pred_proba)
    plt.figure(figsize=(8, 6))
    plt.plot(thresholds, precisions[:-1], "b--", label="Precision")
    plt.plot(thresholds, recalls[:-1], "g-", label="Recall")
    plt.xlabel("Threshold")
    plt.legend(loc="center left")
    plt.ylim([0, 1])
    plt.title("Precision-Recall vs Threshold <Best Choice>")
    plt.grid(True)
    plt.savefig('precision_recall_threshold.svg', dpi=1200, bbox_inches='tight')
    plt.show()

    # 映射 PCA 特征重要性到原始特征
    # =============================
    # 假设你是在 train_data 中传入了标准化后的 PCA 数据
    # 我们需要从全局或通过参数传入原始 X 列名和 pca 对象
    # 这里我们假设：
    global original_feature_names, pca, scaler  # 在 train_data 中定义并保存这些变量

    # 获取 PCA 的 components_ 和模型的 feature_importances_
    components = pca.components_  # shape: (n_components, n_original_features)
    importances = best_rf.feature_importances_  # shape: (n_components, )

    # 加权平均：每个成分 × 其在模型中的重要性
    weighted_components = np.abs(components.T * importances)  # 转置为 (n_original, n_components)
    summed_weights = weighted_components.sum(axis=1)

    # 构建原始特征的重要性 Series
    original_importances = pd.Series(summed_weights, index=original_feature_names)
    original_importances_sorted = original_importances.sort_values(ascending=False)

    print("Top 20 Features (Mapped from PCA):")
    print(original_importances_sorted.head(20))

    # 可视化
    plt.figure(figsize=(12, 8))
    sns.barplot(x=original_importances_sorted.values, y=original_importances_sorted.index)
    plt.title('Feature Importances Mapped from PCA Components')
    plt.xlabel('Importance')
    plt.ylabel('Features')
    plt.tight_layout()
    plt.savefig('mapped_feature_importances.svg', dpi=1200, bbox_inches='tight')
    plt.show()

    # 调整阈值的结果
    with open('precision_recall_threshold.txt', 'w') as out:
        out.write(f"最佳参数: {grid_search.best_params_}\n")
        out.write("\nTop 20 Features (Mapped from PCA):\n")
        out.write(original_importances_sorted.head(20).to_string())
        out.write("\n\n")
        for threshold in np.arange(0.1, 0.9, 0.05):
            y_pred_custom = (y_pred_proba >= threshold).astype(int)
            print(classification_report(test_y, y_pred_custom, digits=4, target_names=le.classes_))
            out.write(f"Threshold: {threshold:.2f}\n")
            out.write(classification_report(test_y, y_pred_custom, digits=4, target_names=le.classes_))

    return best_rf



def gridSearch_xgboost(x_data, y_data, test_x, test_y, le):
    """
    使用GridSearchCV为XGBoost模型寻找最佳参数。
    """
    print('------------------ XGBoost GridSearch 开始 --------------------')

    # 1. 定义你要搜索的XGBoost参数范围
    # 注意：XGBoost的参数名与RandomForest不同
    param_grid = {
        'n_estimators': [100, 200],  # 树的数量
        # 'max_depth': [6, 8],  # 树的最大深度
        'learning_rate': [0.1, 0.05],  # 学习率，XGBoost的关键参数
        'subsample': [0.8],  # 训练每棵树时，随机抽样的样本比例
        'colsample_bytree': [0.8],  # 训练每棵树时，随机抽样的特征比例
        # 'gamma': [0, 0.1],                    # 节点分裂所需的最小损失减少量，用于防止过拟合
        # 'min_child_weight': [1, 5]          # 子节点中实例权重的最小和，用于防止过拟合
    }

    # 2. 计算scale_pos_weight来处理类别不平衡
    # scale_pos_weight = count(negative class) / count(positive class)
    # 假设类别0是多数类（Benign），类别1是少数类（DDoS）
    scale_pos_weight = np.bincount(y_data)[0] / np.bincount(y_data)[1]
    print(f"计算出的 scale_pos_weight (类别0/类别1): {scale_pos_weight:.2f}")

    # 3. 创建XGBoost分类器
    # 我们将scale_pos_weight作为固定参数传入，因为它是由数据决定的，而不是需要搜索的超参数
    xgb_classifier = xgb.XGBClassifier(
        objective='binary:logistic',  # 二分类问题的目标函数
        eval_metric='logloss',  # 评估指标
        use_label_encoder=False,  # 推荐设置，避免警告
        scale_pos_weight=scale_pos_weight,
        random_state=42
    )

    # 4. 定义我们的评估指标
    f1_scorer = make_scorer(f1_score, average='macro')

    # 5. 创建GridSearchCV对象
    grid_search = GridSearchCV(
        estimator=xgb_classifier,
        param_grid=param_grid,
        scoring=f1_scorer,
        cv=3,
        verbose=2,
        n_jobs=-1
    )

    # 6. 在训练数据上执行搜索
    grid_search.fit(x_data, y_data)

    # 7. 查看最佳参数和最佳模型
    print("XGBoost 最佳参数:", grid_search.best_params_)
    best_xgb = grid_search.best_estimator_

    # 8. 使用这个最佳模型进行预测和评估
    y_pred = best_xgb.predict(test_x)
    print("XGBoost 默认阈值(0.5)下的分类报告:")
    print(classification_report(test_y, y_pred, digits=4, target_names=le.classes_))
    print('------------------ XGBoost GridSearch 测试完毕 --------------------')

    # 后续的图表绘制和阈值分析逻辑与之前完全相同

    # Precision-Recall vs Threshold 图
    y_pred_proba = best_xgb.predict_proba(test_x)[:, 1]
    precisions, recalls, thresholds = precision_recall_curve(test_y, y_pred_proba)
    plt.figure(figsize=(8, 6))
    plt.plot(thresholds, precisions[:-1], "b--", label="Precision")
    plt.plot(thresholds, recalls[:-1], "g-", label="Recall")
    plt.xlabel("Threshold")
    plt.legend(loc="center left")
    plt.ylim([0, 1])
    plt.title("XGBoost Precision-Recall vs Threshold")
    plt.grid(True)
    plt.savefig('xgboost_pr_threshold.svg', dpi=1200, bbox_inches='tight')
    plt.show()

    # 调整阈值的结果写入文件
    with open('xgboost_threshold_analysis.txt', 'w') as out:
        out.write(f"XGBoost 最佳参数: {grid_search.best_params_}\n\n")
        for threshold in np.arange(0.1, 0.9, 0.05):
            y_pred_custom = (y_pred_proba >= threshold).astype(int)
            out.write(f"Threshold: {threshold:.2f}\n")
            out.write(classification_report(test_y, y_pred_custom, digits=4, target_names=le.classes_))
            out.write("\n")

    # 特征重要性
    # XGBoost的feature_importances_默认是基于'weight'（特征被使用的次数）
    # 'gain'（平均增益）或 'cover'（平均覆盖度）通常更有信息量
    importances = pd.Series(best_xgb.get_booster().get_score(importance_type='gain'), index=x_data.columns)
    # 如果有特征从未使用过，它们不会出现在get_score的结果中，需要填充为0
    importances = importances.reindex(x_data.columns, fill_value=0)
    importances_sorted = importances.sort_values(ascending=False)

    plt.figure(figsize=(12, 15))
    sns.barplot(x=importances_sorted, y=importances_sorted.index)
    plt.title('XGBoost Feature Importances (Gain)')
    plt.ylabel('Feature')
    plt.xlabel('Importance (Gain)')
    plt.savefig('xgboost_feature_importances.svg', dpi=1200, bbox_inches='tight')
    plt.show()



# 读取CSV文件
def load_file(file_path):
    return pd.read_csv(file_path)

def test1():
    # 获取所有唯一的标签
    unique_labels = df['Label'].unique()
    print(df['Label'][0])
    print("Unique labels:", unique_labels)

    # 查找包含特定标签的行，例如 'Infilteration'
    infiltration_rows = df[df['Label'] == 'Infilteration']
    print(infiltration_rows)


def data_ratio(df_data):
    # 假设只保留 'Benign' 和 'Infilteration' 两类
    selected_labels = ['BENIGN', 'DDoS', 'Label', 'Syn']
    filtered_df = df_data[df_data['Label'].isin(selected_labels)]

    # 统计每类的数量和比例
    label_counts = filtered_df['Label'].value_counts()
    label_percentages = label_counts / label_counts.sum() * 100

    print("Selected labels count:\n", label_counts)
    print("Selected labels percentage:\n", label_percentages.round(2))

def data_clean(df_data):
    # 移除包含空值或无穷大的行，并且 Label 不等于 'Label'
    df_clean = df_data.dropna() \
                       .replace([np.inf, -np.inf], np.nan) \
                       .dropna() \
                       .loc[df_data['Label'] != 'Label']
    return df_clean

def data_preprocess(df_data):
    # 假设df已经经过清洗和编码
    # 1. 准备数据
    # types = ['Flow ID', 'Source IP', 'Source Port', 'Destination IP', 'Destination Port', 'Protocol', 'Timestamp', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std', 'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean', 'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length', 'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length', 'Max Packet Length', 'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio', 'Average Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size', 'Fwd Header Length.1', 'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate', 'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes', 'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward', 'Active Mean', 'Active Std', 'Active Max', 'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min', 'Label']
    #
    # print('cols', types)
    # for col in types:
    #     if col == 'Label' or col == 'Timestamp':
    #         continue
    #     df_data[col] = pd.to_numeric(df_data[col], errors='coerce')
    #     # 打印当前列的最大值
    #     # print(f"Max value in column '{col}':", df_data[col].max())
    #
    #     # 将浮点型数值转为 int 类型（向下取整）
    #     # print('current column', col)
    #     # if df_data[col].dtype != object:  # 确保是数值类型
    #     #     df_data[col] = df_data[col].fillna(0).astype(int)
    # print("Data types of features:\n", df_data.dtypes)
    columns_to_drop = ['Flow ID', 'Source IP', 'Destination IP']
    df_data = df_data.drop(columns=columns_to_drop)
    return df_data

def preprocess(df_data):
    print('----------------start preprocess--------------------')
    df_data.columns = df_data.columns.str.strip()
    print(df_data.columns.tolist())
    print('----------------data column header processed----------------------')
    data_ratio(df_data)
    tmp = data_clean(df_data)
    data_ratio(df_data)
    print('----------------data clean end----------------------')
    print("Data types of features:\n", df_data.dtypes)
    print('----------------data preprocess start----------------------')
    tmp = data_preprocess(tmp)
    print("Data types of features:\n", df_data.dtypes)
    # tmp = data_clean(tmp)
    data_ratio(tmp)
    print('----------------data preprocess end------------------------')
    return tmp


def get_data(dataset, label):
    return dataset[dataset['Label'] == label]

def merge_data(ds1, ds2):
    return pd.concat([ds1, ds2], ignore_index=True)


if __name__ == '__main__':
    # data_list = [ 'cse_cic_ids_2018/Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv',
    #              'cse_cic_ids_2018/Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv']
    # datas = []
    df = load_file('cic_ddos_2019/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv')
    # df1 = load_file('cic_ddos_2019/Syn.csv')
    df = preprocess(df)
    # df1 = preprocess(df1)
    # df1.loc[df1['Label'] == 'Syn', 'Label'] = 'DDoS'
    # df = merge_data(df, df1)
    # df = get_data(df, 'Benign')
    # for file in data_list:
    #     print('-------------------file process start-----------------')
    #     print('file name:', file)
    #     tp = load_file(file)
    #     tp = preprocess(tp)
    #     tp = get_data(tp, 'Infilteration')
    #     datas.append(tp)
    #     print('-------------------file process end----x---------------')
    # ddos = merge_data(datas[0], datas[1])
    # df = merge_data(df, ddos)

    print('-------------------data process result-------------------')
    data_ratio(df)
    print('-------------------data process result end-------------------')

    train_data(df)