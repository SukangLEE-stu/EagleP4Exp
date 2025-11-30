import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
import data.tools.data_analyse as da

def load_data(num_features, data_dir):
    row_data = pd.read_csv('data/data.csv')
    row_data = da.preprocess(row_data)

    # 按照列进行处理

    # 通过入参挑选特征数量
    # 适用于数据平面的特征列表
    data_plane_features = [ \
          # 'Fwd IAT Total',
          'Bwd Packet Length Max',
          'Destination Port',
          'Fwd Packet Length Max',
          # 'Bwd IAT Max',
          # 'Bwd IAT Total',
          'Total Length of Fwd Packets',
          'Bwd Packet Length Min',
          ][:num_features]
    # used_features = ['SepalLengthCm', 'SepalWidthCm', 'PetalLengthCm', 'PetalWidthCm'][:num_features]
    X = row_data[data_plane_features]
    y = row_data['Label']

    print("--------------------------------")
    print("X 的前十行：")
    print(X.head(10))
    print("\ny 的前十行：")
    print(y[:10])
    print("--------------------------------")

    encoder = LabelEncoder()
    y = encoder.fit_transform(y)


    train_X, test_X, train_y, test_y = train_test_split(X, y, test_size = 0.3, random_state = 101, shuffle=True)
    return train_X, train_y, test_X, test_y, data_plane_features
