import numpy as np
import random

def ten_to_bin(num,count):
    num = bin(num).lstrip('0b')

    if len(num) != count:
        cont = count - len(num)
        num = int(cont) * '0' + num
    return num

def find_fist_diff_bit(dict1,dict2,code_len):
    code1 = ten_to_bin(dict1, code_len)
    code2 = ten_to_bin(dict2, code_len)
    count = 0
    for i in range(code_len):
        if code1[i]!=code2[i]:
            break
        count+=1
    return code_len - count

def get_mask(count,code_len):

    return (2**code_len-1)&((2**code_len-1)<<count)

def get_value(mask,dict):

    return mask&dict

def tenary_test(test_value,mask,value):
    return test_value&mask == value&mask

# TODO：这个是阻塞点，遍历实现的
def Table_to_TCAM(table, code_len):
    # print('table is', table)
    TCAM_table={}
    # code_len = 32

    # separation_value_input = list(table.keys())
    table_len = len(table)

    # list = [4]
    # mask = naive_mask(list,4)
    # print(ten_to_bin(mask,4))
    # print(ten_to_bin(naive_value(mask,list),4))
    # table_values = []
    # previous_class = table[np.sort(separation_value_input)[0]]
    Table={}
    initial = table[table_len - 1]
    pre = table_len - 1
    idx = table_len - 2
    while idx > 0:
        if initial != table[idx]:
            Table[pre] = initial
            pre = idx
            initial = table[idx]
        idx -= 1
    Table[pre] = initial
    Table[0] = table[0]

    # for dict in sorted(separation_value_input, reverse=True):
    #     if dict == initial:
    #         Table[dict] = table[dict]
    #         lasat_lable = table[dict]
    #     if table[dict] != lasat_lable:
    #         Table[dict] = table[dict]
    #         lasat_lable = table[dict]
    #     if dict == 0:
    #         Table[dict] = table[dict]
        # print(table[dict])
        # table_values += [table[dict]]
    #
    # max_value = max(table, key = table.count)
    # print('max_value is', max_value)

    # unique_range_Table = {}
    # for dict in sorted(separation_value_input, reverse=True):
    #     if dict == initial:
    #         unique_range_Table[dict] = table[dict]
    #         unique_range_lasat_lable = table[dict]
    #     if str(table[dict]) != str(max_value):
    #         if table[dict] != unique_range_lasat_lable:
    #             unique_range_Table[dict] = table[dict]
    #             unique_range_lasat_lable = table[dict]
    #         if dict == 0:
    #             unique_range_Table[dict] = table[dict]
    # print('table_values is', table_values)
    # print('unique_range_values is', unique_range_Table)
    # guess_errors = 0
    priority = 0
    separation_value = list(Table.keys())
    print('Begin transfer, separation_value is', separation_value)
    print('Table is', Table)
    if 0 not in separation_value:
        separation_value += [0]
    boundaries = sorted(separation_value, reverse=True)
    for i, bound in enumerate(boundaries):
        value_flag = bound

        if bound ==0:
            bits = find_fist_diff_bit(bound, bound, code_len)
            mask = get_mask(bits, code_len)
            value = get_value(mask, value_flag)
            TCAM_table[priority] = [mask, value, Table[bound]]
            break
        # if bound ==68:
        #     print("check")
        bits = find_fist_diff_bit(bound, boundaries[i + 1], code_len) - 1
        if bits < 0:
            print("----error----", value_flag)
        mask = get_mask(bits, code_len)
        value = get_value(mask, value_flag)
        TCAM_table[priority] = [mask, value, Table[bound]]
        priority += 1
        value_flag -= 1
        while True:
            if value_flag == boundaries[i+1] or value_flag<0:
                break
            if value_flag >= table_len:
                value_flag -= 1
                continue
            if not tenary_test(value_flag, mask, value) :
                bits = find_fist_diff_bit(value_flag, boundaries[i + 1], code_len) - 1

                mask = get_mask(bits, code_len)
                value = get_value(mask, value_flag)
                TCAM_table[priority] = [mask, value, Table[bound]]
                priority += 1
            value_flag -= 1


    print('Input table has: ',len(table),'entries and: ', len(separation_value),' different ranges, range match with default: ', len(list(Table.keys())),', and output TCAM entry has', len(list(TCAM_table.keys())))
    print('range match with default: ', len(list(Table.keys())))
    # print('TCAM_table is', TCAM_table)
    match = 0
    counts = 0
    correct_match = 0
    keys = list(TCAM_table.keys())
    # separation_value = list(table.keys())

    for dict in range(table_len):
        counts += 1
        error_switch = True
        for count in sorted(keys):
            if dict & TCAM_table[count][0] == TCAM_table[count][0] & TCAM_table[count][1]:
                match += 1

                if table[dict] == TCAM_table[count][2]:
                    correct_match += 1
                    error_switch = False
                break

        if error_switch == True:
            print("error: ", dict)

        print('\r{}th testing sample with correct matches: {} % and {} errors.'.format( counts,   100*correct_match / counts ,
              counts - correct_match),end=" " )


    return TCAM_table

def generate_test_exact_table(entry):
    table = {}
    type = 0

    for i in range(entry):

        if np.random.rand() < 0.5:
            x = np.random.rand()
            if x > 0.6:
                type = 1
            elif x < 0.33:
                type = 2
            else:
                type = 0

        table[i] = type
    return table

if __name__ == "__main__":
    np.random.seed(1)
    table = generate_test_exact_table(100000)

    code_len = 32


    TCAM_table = Table_to_TCAM(table, code_len)


    match = 0
    counts = 0
    correct_match = 0
    keys = list(TCAM_table.keys())
    separation_value = list(table.keys())

    for dict in np.sort(separation_value):
        counts += 1
        error_switch = True
        for count in np.sort(keys):
            if dict & TCAM_table[count][0] == TCAM_table[count][0] & TCAM_table[count][1]:
                match += 1

                if table[dict]==TCAM_table[count][2]:
                    correct_match += 1
                    # print('hh')
                    error_switch = False
                break

        if error_switch == True:
            print("error: ",dict)


    print('\n', match/ counts,' numbers matches and:',correct_match/ counts, ' numbers of correct match with:', counts-correct_match,' errors.')
