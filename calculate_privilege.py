'''
CPM Privilege Calculator
Copyright (c) 2025 The Charles Stark Draper Laboratory, Inc

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
“Software”), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
'''

import sys
import yaml
import argparse

# Four operation types
ops = ["READ", "WRITE", "CALL", "RETURN"]

# Calculate the privilege of a given compartmentalization c and whether or not to assume W-XOR-X
def calculate_privilege(c, weights, wxorx):

    print(f"Write-XOR-Execute: {wxorx}")
    subjs = []
    objs = []
    subj_op_counts = {}

    obj_sizes = {}
    subj_sizes = {}

    # Weight by operation type
    subj_weights = {}
    obj_weights = {}
    for op in ops:
        subj_weights[op] = {}
        obj_weights[op] = {}

    privilege = {}
    for op in ops:
        privilege[op] = 0
    
    for subj_descriptor in c['subject_map']:
        subj = subj_descriptor['name']
        subjs.append(subj)
        subjects = subj_descriptor["subjects"]
        sizes = subj_descriptor.get("sizes", [1] * len(subjects))
        subj_sizes[subj] = sum(sizes)
        for op in ops:
            subj_weights[op][subj] = 0
            for i in range(0, len(sizes)):
                subj_weights[op][subj] += apply_weight(sizes[i], weights[op].get(subjects[i], "1"))

        num_funcs = len(subjects)

        subj_op_counts[subj] = {}
        subj_op_counts[subj]["READ"] = subj_descriptor.get("read_instructions", num_funcs)
        subj_op_counts[subj]["WRITE"] = subj_descriptor.get("write_instructions", num_funcs)
        subj_op_counts[subj]["CALL"] = subj_descriptor.get("call_instructions", num_funcs)
        subj_op_counts[subj]["RETURN"] = subj_descriptor.get("return_instructions", num_funcs)

    for obj_descriptor in c['object_map']:
        obj = obj_descriptor['name']
        objs.append(obj)
        objects = obj_descriptor["objects"]
        sizes = obj_descriptor.get("sizes", [1] * len(subjects))
        obj_sizes[obj] = sum(sizes)
        for op in ops:
            obj_weights[op][obj] = 0
            for i in range(0, len(sizes)):
                weight = apply_weight(sizes[i], weights[op].get(objects[i], "1"))
                obj_weights[op][obj] += weight

    for principal in c['privileges']:
        subject = principal['principal']['subject']

        privilege["CALL"] += subj_op_counts[subject]["CALL"] * subj_weights["CALL"][subject]
        for call_domain in principal['can_call']:
            if call_domain == subject:
                continue
            if call_domain in subj_op_counts:
                privilege["CALL"] += subj_op_counts[subject]["CALL"] * subj_weights["CALL"][call_domain]
            else:
                print(f"Subject {can_call} not found")

        privilege["RETURN"] += subj_op_counts[subject]["RETURN"] * subj_weights["RETURN"][subject]
        for return_domain in principal['can_return']:
            if return_domain == subject:
                continue
            if return_domain in subj_op_counts:
                privilege["RETURN"] += subj_op_counts[subject]["RETURN"] * subj_weights["RETURN"][return_domain]
                
            else:
                print(f"Subject {return_domain} not found")

        for read_descriptor in principal['can_read']:
            for obj_domain in read_descriptor['objects']:
                if obj_domain in obj_weights["READ"]:
                    privilege["READ"] += subj_op_counts[subject]["READ"] * obj_weights["READ"][obj_domain]
                else:
                    print(f"Object {obj_domain} not found")
                    
        for write_descriptor in principal['can_write']:
            for obj_domain in write_descriptor['objects']:
                if obj_domain in obj_weights["READ"]:
                    privilege["WRITE"] += subj_op_counts[subject]["WRITE"] * obj_weights["WRITE"][obj_domain]
                else:
                    print(f"Object {obj_domain} not found")

    # Now calculate monolithic privilege
    mono_priv = {}
    for op in ops:
        mono_priv[op] = 0

    all_data_size = {}
    all_code_size = {}

    for op in ops:
        all_data_size[op] = 0
        all_code_size[op] = 0

        for s in subj_weights[op]:
            all_code_size[op] += subj_weights[op][s]
        for o in obj_weights[op]:
            all_data_size[op] += obj_weights[op][o]

    for principal in c['privileges']:
        subject = principal['principal']['subject']
        mono_priv["READ"] += subj_op_counts[subject]["READ"] * all_data_size["READ"]
        mono_priv["WRITE"] += subj_op_counts[subject]["WRITE"] * all_data_size["WRITE"]
        mono_priv["CALL"] += subj_op_counts[subject]["CALL"] * all_code_size["CALL"]
        mono_priv["RETURN"] += subj_op_counts[subject]["RETURN"] * all_code_size["RETURN"]

        # With no W^X, you can read/write code and call/return data
        if not wxorx:
            mono_priv["READ"] += subj_op_counts[subject]["READ"] * all_code_size["READ"]
            mono_priv["WRITE"] += subj_op_counts[subject]["WRITE"] * all_code_size["WRITE"]
            mono_priv["CALL"] += subj_op_counts[subject]["CALL"] * all_data_size["CALL"]
            mono_priv["RETURN"] += subj_op_counts[subject]["RETURN"] * all_data_size["RETURN"]

    #print(f"Priv: {privilege}")
    #print(f"Mono Priv: {mono_priv}")
    PSR = calculate_PSR(privilege, mono_priv)

    print("PSR: ")
    for key in PSR:
        print(f"{key}\t{PSR[key]}")

# Read weight file and return a dict indexed by subj/obj, and op, and then holds a weight
def parse_weight_file(filename):

    try:
        f = open(filename, "r")
    except Exception as e:
        print("Unable to open file " + filename)
        return {}

    weights = {}
    for op in ops:
        weights[op] = {}

    lines = f.readlines()
    weights_found = 0
    for l in lines:
        l = l.strip()
        if len(l) == 0:
            continue
        if l[0] == "#":
            continue
        fields = l.split(",")
        if len(fields) != 5:
            raise Exception(f"Invalid weight file, did not have 5 fields on line '{l}'")
        entity_id = fields[0].strip()
        weights["READ"][entity_id] = fields[1].strip()
        weights["WRITE"][entity_id] = fields[2].strip()
        weights["CALL"][entity_id] = fields[3].strip()
        weights["RETURN"][entity_id] = fields[4].strip()
        weights_found += 1

    print(f"Read {weights_found} privilege weights from {filename}")
    return weights

def apply_weight(value, weight_string):

    if weight_string == "":
        return value

    if weight_string[0] == "=":
        return value * int(weight_string[1:])
    else:
        return value * int(weight_string)

def calculate_PSR(comp_priv, mono_priv):

    result = {}

    total_comp_priv = 0
    total_mono_priv = 0

    for op in ops:
        total_comp_priv += comp_priv[op]
        total_mono_priv += mono_priv[op]

        result[op] = comp_priv[op] / mono_priv[op]

    result["TOTAL"] = total_comp_priv / total_mono_priv

    return result

if __name__ == '__main__':

    description = f"CPM Privilege Calculator"
    parser = argparse.ArgumentParser(description=description)

    parser.add_argument('compfile', help='Compartmentalization YAML file')
    parser.add_argument('--weight-file', help="Additional weight csv file")
    parser.add_argument('--wxorx', action=argparse.BooleanOptionalAction, help="Adds the assumption of write-xor-execute memory permissions", default=False)

    args = parser.parse_args()
    wxorx = args.wxorx != False

    # See if we have a weight file and parse it
    if args.weight_file != None:
        weights = parse_weight_file(args.weight_file)
    else:
        weights = {}
        for op in ops:
            weights[op] = {}

    # Open the file
    try:
        f = open(args.compfile, 'r')
    except Exception as e:
        print("Error: Unable to open file " + args.compfile)
        exit()

    # Parse as yaml
    try:
        c = yaml.safe_load(f)
    except yaml.YAMLError as e:
        print("Error parsing yaml file: " + args.compfile)
        exit()

    # Calculate privileges on it
    calculate_privilege(c, weights, wxorx)
