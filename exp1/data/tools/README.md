# 数据分析

## TODO
1. 需要补做一个XGBoost+\**的主成分分析

## PS
数据集有很多行表头，需要筛选
```text
/Users/eagle/myworkspace/P4Exp/venv/bin/python3.9 /Users/eagle/myworkspace/P4Exp/eagle_tools/data_analyse.py 
/Users/eagle/myworkspace/P4Exp/eagle_tools/data_analyse.py:4: DtypeWarning: Columns (0,1,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78) have mixed types. Specify dtype option on import or set low_memory=False.
  df = pd.read_csv('cse_cic_ids_2018/data.csv')
Benign
Unique labels: ['Benign' 'Label' 'Infilteration']
        Dst Port  Protocol  Timestamp  ...  Idle Max  Idle Min  Label
21838   Dst Port  Protocol  Timestamp  ...  Idle Max  Idle Min  Label
43117   Dst Port  Protocol  Timestamp  ...  Idle Max  Idle Min  Label
63291   Dst Port  Protocol  Timestamp  ...  Idle Max  Idle Min  Label
84013   Dst Port  Protocol  Timestamp  ...  Idle Max  Idle Min  Label
107719  Dst Port  Protocol  Timestamp  ...  Idle Max  Idle Min  Label
132409  Dst Port  Protocol  Timestamp  ...  Idle Max  Idle Min  Label
154205  Dst Port  Protocol  Timestamp  ...  Idle Max  Idle Min  Label
160206  Dst Port  Protocol  Timestamp  ...  Idle Max  Idle Min  Label
202680  Dst Port  Protocol  Timestamp  ...  Idle Max  Idle Min  Label
228583  Dst Port  Protocol  Timestamp  ...  Idle Max  Idle Min  Label
247717  Dst Port  Protocol  Timestamp  ...  Idle Max  Idle Min  Label
271676  Dst Port  Protocol  Timestamp  ...  Idle Max  Idle Min  Label
296994  Dst Port  Protocol  Timestamp  ...  Idle Max  Idle Min  Label
322938  Dst Port  Protocol  Timestamp  ...  Idle Max  Idle Min  Label
344162  Dst Port  Protocol  Timestamp  ...  Idle Max  Idle Min  Label
349509  Dst Port  Protocol  Timestamp  ...  Idle Max  Idle Min  Label
355079  Dst Port  Protocol  Timestamp  ...  Idle Max  Idle Min  Label
360660  Dst Port  Protocol  Timestamp  ...  Idle Max  Idle Min  Label
366039  Dst Port  Protocol  Timestamp  ...  Idle Max  Idle Min  Label
367413  Dst Port  Protocol  Timestamp  ...  Idle Max  Idle Min  Label
368613  Dst Port  Protocol  Timestamp  ...  Idle Max  Idle Min  Label
371159  Dst Port  Protocol  Timestamp  ...  Idle Max  Idle Min  Label
377704  Dst Port  Protocol  Timestamp  ...  Idle Max  Idle Min  Label
399543  Dst Port  Protocol  Timestamp  ...  Idle Max  Idle Min  Label
420822  Dst Port  Protocol  Timestamp  ...  Idle Max  Idle Min  Label
440996  Dst Port  Protocol  Timestamp  ...  Idle Max  Idle Min  Label
461718  Dst Port  Protocol  Timestamp  ...  Idle Max  Idle Min  Label
485424  Dst Port  Protocol  Timestamp  ...  Idle Max  Idle Min  Label
510114  Dst Port  Protocol  Timestamp  ...  Idle Max  Idle Min  Label
534073  Dst Port  Protocol  Timestamp  ...  Idle Max  Idle Min  Label
559391  Dst Port  Protocol  Timestamp  ...  Idle Max  Idle Min  Label
585335  Dst Port  Protocol  Timestamp  ...  Idle Max  Idle Min  Label
606559  Dst Port  Protocol  Timestamp  ...  Idle Max  Idle Min  Label

[33 rows x 80 columns]
```

