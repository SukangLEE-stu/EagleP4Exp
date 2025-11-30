import data.data_preprocess as dp
import tools.table_transfer as tt
import tools.p4.p4_code_creator as code_gen_tool

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

code_gen_tool.main()


if_using_subprocess = False
test_model_path = Planter_config['directory config']['work']+'/src/targets/'+Planter_config['target config']['device'] +'/'+Planter_config['target config']['type']
print('= Add the following path: '+test_model_path)
sys.path.append(test_model_path)
run_model_main = importlib.util.spec_from_file_location("*", test_model_path+"/run_model.py")
run_model_functions = importlib.util.module_from_spec(run_model_main)
run_model_main.loader.exec_module(run_model_functions)
processes, if_using_subprocess = run_model_functions.main(if_using_subprocess)

test_model_main = importlib.util.spec_from_file_location("*", test_model_path+"/test_model.py")
test_model_functions = importlib.util.module_from_spec(test_model_main)
test_model_main.loader.exec_module(test_model_functions)
processes, if_using_subprocess = test_model_functions.main(sklearn_test_y, test_X, test_y, processes, if_using_subprocess)

if if_using_subprocess:
    print('Join all subprocess together ...')
    try:
        for p in processes:
            p.join()
    except Exception as e:
        print(str(e))