import os
import sys
import stat
import subprocess as sub
import json
import time
import signal
import platform
import threading
import getpass
from multiprocessing import *
from common.json_tool import *


def file_names(eagle_config):
    work_root = './'
    model_test_root = 'common/model_test/test_environment'
    file_name = 'auto_generated.p4'
    test_file_name = 'test_in_p4'
    return work_root, model_test_root, file_name, test_file_name


def run_command(command, root):
    print('start config is', command, root, 'work dir:', os.getcwd())
    sub.run('ls', cwd = os.getcwd() + '/' + root)
    sub.run('./' + command, cwd = os.getcwd() + '/' + root)

def write_common_test_classification(fname, eagle_config):
    work_dir = './'
    num_features = eagle_config['features']
    send_port = eagle_config['test config']['port']

    with open('common/model_test/test_environment/' + fname, 'a') as test:
        test.write("import json\n"
                   "import numpy as np\n"
                   "from scapy.all import *\n"
                   "from sklearn.metrics import *\n"
                   "from multiprocessing import *\n" 
                   "import readline\n"
                   "import time\n"
                   "import os\n"
                   "print('Predicted load table time ... ("+str(predicted_time)+"s)')\n"
                   "time.sleep("+str(predicted_time)+")\n")

        test.write("class Planter(Packet):\n"
                   "    name = 'Planter'\n"
                   "    fields_desc = [StrFixedLenField('P', 'P', length=1),\n"
                   "        StrFixedLenField('Four', '4', length=1),\n"
                   "        XByteField('version', 0x01),\n"
                   "        XByteField('type', 0x01),\n")
        for f in range(num_features):
            test.write("        IntField('feature" + str(f) + "', 0),\n")
        test.write("        IntField('result', 0xDEADBABE)]\n\n")

        test.write("bind_layers(Ether, Planter, type=0x1234)\n\n")

        data_file = '../../../target/logs/Test_Data.json'
        test.write("config_file = '" + data_file + "'\n"
                                                   "Test_Data = json.load(open(config_file, 'r'))\n"
                                                   "sklearn_test_y = Test_Data['sklearn_test_y']\n"
                                                   "test_X = Test_Data['test_X']\n"
                                                   "test_y = Test_Data['test_y']\n\n")

        test.write("def send_receive_extract(pkt, iface, received_result):\n"
                   "    resp = srp1(pkt, iface=iface, timeout=1, verbose=False)\n"
                   "    if resp:\n"
                   "        receive_info = resp[Planter]\n"
                   "        if receive_info:\n"
                   "            received_result.value = int(receive_info.result)\n"
                   "        else:\n"
                   "            print('\\rCannot find Planter header in the {}th packet |'.format(i), end='')\n"
                   "    else:\n"
                   "        print('\\rDid not receive response of the {}th packet |'.format(i), end='')\n\n")

        test.write(
            "print(\"\\n==============================================================================================\")\n"
            "print(\"=        Two steps to exit Planter: 1. input 'exit', press 'return'; 2. press ctrl + c       =\")\n"
            "print(\"==============================================================================================\")\n"
            "print('Test the switch model, the result should be the same as previous python test')\n"
            "same = 0\n"
            "correct = 0\n"
            "error = 0\n"
            "switch_test_y = []\n\n"
            "for i in range(np.shape(test_X)[0]):\n"
            "    iface = '" + send_port + "'\n"
                                          "    pkt = Ether(dst='00:04:00:00:00:00', type=0x1234) / Planter( ")

        for f in range(num_features):
            test.write("feature" + str(f) + " = int(test_X[i][" + str(f) + "]), ")
        test.write("result  = int(404))\n")

        test.write("    pkt = pkt/' '\n\n"
                   "    received_result = Manager().Value('i', 404)\n\n"
                   "    s_r_e = Process(target=send_receive_extract, args=(pkt,iface,received_result,))\n"
                   "    s_r_e.daemon = True\n"
                   "    s_r_e.start()\n"
                   "    s_r_e.join()\n\n"
                   "    switch_prediction = received_result.value\n"
                   "    switch_test_y += [switch_prediction]\n\n"
                   "    if switch_prediction == test_y[i]:\n"
                   "        correct += 1\n"
                   "    if switch_prediction == sklearn_test_y[i]:\n"
                   "        same += 1\n"
                   "    else:\n"
                   "        error += 1\n"
                   # "    if i % 10 == 0 and i != 0:\n"  
                   "    print( '\\rSwitch model {}th prediction: {}, test_y: {}, with acc: {:.3}, with acc to sklearn:"
                   " {:.4}, with error: {:.4}, M/A format macro f1: {:.4}, macro f1: {:.4}'"
                   ".format(i+1, switch_prediction, test_y[i], correct / (i + 1), same / (i + 1),"
                   " error / (i + 1), accuracy_score(switch_test_y[:i+1], test_y[:i+1]), accuracy_s"
                   "core(sklearn_test_y[:i+1], test_y[:i+1])), end='')\n"
                   "result = classification_report(switch_test_y, test_y, digits=4)\n"
                   "print('\\n\\n', result)\n")
        test.write("print(\"======================================= Test Finished ========================================\")\n")

def finish_runtime(eagle_config):
    work_root, model_test_root, file_name, test_file_name = file_names(eagle_config)
    # table_entries_file = 'target/logs/Runtime.json'
    # Table_entries = json.load(open(table_entries_file, 'r'))
    Runtime = {}
    Runtime["target"] = "bmv2"
    Runtime["p4info"] = model_test_root+"/logs/"+file_name+".p4.p4info.txt"
    Runtime["bmv2_json"] = model_test_root+"/logs/"+file_name+".json"
    # Runtime["table_entries"] = Table_entries["table_entries"]
    json.dump(Runtime, open('target/logs/s1-runtime.json', 'w'), indent=4)




def simple_count(file_name):
    lines = 0
    for current_line in open(file_name):
        if 'register' in current_line:
            lines += 300
        lines += 1
    return lines




def generate_test_file(config_file):
    eagle_config = json.load(open(config_file, 'r'))

    file_name = 'auto_generated.p4'
    test_file = 'test_in_p4.py'

    ##################################################
    # predict time
    commands_file = 'target/s1-commands.txt'
    lines = simple_count(commands_file)
    global predicted_time
    predicted_time = round(lines * 0.00015, 3)
    ##################################################
    print('Generating test files ...' )
    write_common_test_classification(test_file,eagle_config)
    return test_file






def main(sklearn_test_y, test_X, test_y, processes, if_using_subprocess):
    # reload the config file
    config_file = 'target/eagle_config.json'
    eagle_config = json.load(open(config_file, 'r'))
    work_root, model_test_root, file_name, test_file_name = file_names(eagle_config)


    Test_Data = {}
    Test_Data['sklearn_test_y'] = sklearn_test_y
    Test_Data['test_X'] = test_X.values
    Test_Data['test_y'] = test_y

    json.dump(Test_Data, open(work_root + 'target/logs/Test_Data.json', 'w'), indent=4, cls=NpEncoder)

    # =================== generate test the switch file ===================
    test_file = generate_test_file(config_file)
    finish_runtime(eagle_config)

    # =================== test the switch model ===================
    make_run_model_command = 'make_run_model.sh'
    task1_test_model = Process(target=run_command, args=(str(make_run_model_command), str(model_test_root),))
    task1_test_model.daemon = True
    task1_test_model.start()
    processes.append(task1_test_model)

    if not if_using_subprocess:
        if_using_subprocess = True

    return processes, if_using_subprocess


if __name__ == "__main__":
   _ = generate_test_file('target/eagle_config.json')