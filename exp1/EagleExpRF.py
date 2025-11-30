import data.data_preprocess as dp
import tools.table_transfer as tt

# use less data
isTest = True
# test data by python first, then will test on p4
isPythonTest = False

# configs
features = 5

print("Loading data...")
global test_X, test_y
train_X, train_y, test_X, test_y, used_features = dp.load_data(features, None)
print("Data loaded.")

if isTest:
    print("test mode, change data size XD")
    if train_X.shape[0] > 20000:
        train_X = train_X[:20000]
        train_y = train_y[:20000]
    if test_X.shape[0] > 5000:
        test_X = test_X[:5000]
        test_y = test_y[:5000]

print('dataset:', 'train x:', train_X.shape, 'train y:', train_y.shape, 'test x:', test_X.shape,
      'test y:', test_y.shape)

sklearn_test_y = tt.run_model(train_X, train_y, test_X, test_y, used_features)

if isPythonTest:
    try:
        tt.resource_prediction()
    except Exception as e:
        pass
