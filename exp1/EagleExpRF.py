import os

import data.data_preprocess as dp
import tools.table_transfer as tt
import tools.p4.p4_code_creator as code_gen_tool
import common.test_model as test_model
import common.run_model as run_model
import subprocess as sub
# use less data
isTest = True
# test data by python first, then will test on p4
isPythonTest = False

# configs
features = 5

def clean_build_files():
    # sub.run('./clean.sh')
    pass

def train_and_test_with_code_gen():
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
    global sklearn_test_y
    sklearn_test_y = tt.run_model(train_X, train_y, test_X, test_y, used_features)

    if isPythonTest:
        try:
            tt.resource_prediction()
        except Exception as e:
            pass

    code_gen_tool.main()


def do_test_in_p4():
    processes, if_using_subprocess = run_model.main(False)

    processes, if_using_subprocess = test_model.main(sklearn_test_y, test_X, test_y, processes, if_using_subprocess)

    if if_using_subprocess:
        print('Join all subprocess together ...')
        try:
            for p in processes:
                p.join()
        except Exception as e:
            print(str(e))

if __name__ == '__main__':
    clean_build_files()
    train_and_test_with_code_gen()
    do_test_in_p4()