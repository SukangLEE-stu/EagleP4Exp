import os

check_files_cmd = 'aws s3 ls --no-sign-request "s3://cse-cic-ids2018"  --recursive --human-readable --summarize'

files = '''
2018-10-12 00:02:49  336.0 MiB Processed Traffic Data for ML Algorithms/Friday-02-03-2018_TrafficForML_CICFlowMeter.csv
2018-10-12 00:03:10  318.3 MiB Processed Traffic Data for ML Algorithms/Friday-16-02-2018_TrafficForML_CICFlowMeter.csv
2018-10-12 00:03:33  365.1 MiB Processed Traffic Data for ML Algorithms/Friday-23-02-2018_TrafficForML_CICFlowMeter.csv
2018-10-12 00:03:59    3.8 GiB Processed Traffic Data for ML Algorithms/Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv
2018-10-12 00:08:38  102.8 MiB Processed Traffic Data for ML Algorithms/Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv
2018-10-12 00:08:48  358.5 MiB Processed Traffic Data for ML Algorithms/Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv
2018-10-12 00:09:20  364.9 MiB Processed Traffic Data for ML Algorithms/Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv
2018-10-12 00:09:44  341.6 MiB Processed Traffic Data for ML Algorithms/Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv
2018-10-12 00:10:12  313.7 MiB Processed Traffic Data for ML Algorithms/Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv
2018-10-12 00:10:33  199.6 MiB Processed Traffic Data for ML Algorithms/Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv
'''

cmd_prefix = 'aws s3 cp --no-sign-request "s3://cse-cic-ids2018/'
cmd_suffix = '" cse_cic_ids_2018/'

# 如果需要加上 "Processed" 前缀，可以这样：
cmds = ['Processed' + line.strip().split('Processed', 1)[-1] for line in files.strip().split('\n') if 'Processed' in line]
for cmd in cmds:
    exact_cmd = cmd_prefix + cmd + cmd_suffix
    print('execute cmd:', exact_cmd)
    os.system(exact_cmd)
