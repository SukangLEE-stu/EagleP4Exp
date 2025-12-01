import os
import sys
import stat
import subprocess as sub
import json
import time
import signal
import platform
import threading
from multiprocessing import *
import getpass
from common.json_tool import *
from common.log_analyse import *


def file_names(eagle_config):
    work_root = './'
    model_test_root = 'common/model_test/test_environment'
    file_name = 'auto_generated.p4'
    test_file_name = 'test_in_p4'
    return work_root, model_test_root, file_name, test_file_name


def add_make_run_model(fname, config):
    work_root, model_test_root, file_name, test_file_name = file_names(config)
    password = config['test config']['sudo password']
    test_command = 'h1 python3 ' + test_file_name +'.py'
    
    with open(fname, 'w') as command:
        command.write("#!/bin/bash\n")
        command.write("echo '" + password + "' | sudo -S make clean\n")
        command.write("rm " + "*.p4\n")
        command.write("cp "+"../../../target/auto_generated.p4 " + file_name + "\n")
        command.write("cp " + "../../../target/s1-commands.txt " + 's1-commands.txt' + "\n")
        command.write("echo '" + test_command + "' | sudo -S make run\n")
    os.chmod(fname, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)


def term(sig_num, addition):
    print('Killing pid %s with group id %s' % (os.getpid(), os.getpgrp()))
    os.killpg(os.getpgid(os.getpid()), signal.SIGKILL)


def main(if_using_subprocess):
    if platform.system() != 'Linux':
        print('Your system is '+platform.system()+' but not linux, please make sure bmv2, p4c and mininet is installed on your os.')
        exit()
    # =================== set directory config ===================
    # reload the config file
    config_file = 'target/eagle_config.json'
    eagle_config = json.load(open(config_file, 'r'))

    eagle_config['test config']['port'] = 'eth0'
    eagle_config['test config']['sudo password'] = 'lsk11111'

    json.dump(eagle_config, open('target/eagle_config.json', 'w'), indent=4, cls=NpEncoder)

    ##################################################
    work_root, model_test_root, file_name, test_file_name= file_names(eagle_config)
    # =================== compile the generated model ===================
    make_run_model_command = 'common/model_test/test_environment/make_run_model.sh'
    add_make_run_model(make_run_model_command, eagle_config)

    

    # =================== commands in sub process ===================
    # find the current pid
    signal.signal(signal.SIGTERM, term)
    print('current pid is %s' % os.getpid())
    # create the process list
    processes = []

    if_using_subprocess = False

    return processes , if_using_subprocess






