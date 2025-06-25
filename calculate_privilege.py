'''
SEVER Compartment Generator
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
from enum import Enum

# Four operation types
ops = ["READ", "WRITE", "CALL", "RETURN"]

# Calculate the privilege of a given compartmentalization c
def calculate_privilege(c):
    
    subjs = []
    objs = []
    subj_sizes = {}
    obj_sizes = {}
    subj_op_counts = {}
    obj_number_objs = {}

    privilege = {}
    for op in ops:
        privilege[op] = 0
    
    for subj_descriptor in c['subject_map']:
        subj = subj_descriptor['name']
        subjs.append(subj)
        subjects = subj_descriptor["subjects"]
        sizes = subj_descriptor.get("sizes", [1] * len(subjects))
        subj_sizes[subj] = sum(sizes)
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
        obj_number_objs[obj] = len(objects)
        
    for principal in c['privileges']:
        subject = principal['principal']['subject']

        privilege["CALL"] += subj_op_counts[subject]["CALL"] * subj_sizes[subject]
        for call_domain in principal['can_call']:
            if call_domain == subject:
                continue
            if call_domain in subj_sizes:
                privilege["CALL"] += subj_op_counts[subject]["CALL"] * subj_sizes[call_domain]
            else:
                print(f"Subject {can_call} not found")

        privilege["RETURN"] += subj_op_counts[subject]["RETURN"] * subj_sizes[subject]
        for return_domain in principal['can_return']:
            if return_domain == subject:
                continue
            if return_domain in subj_sizes:
                privilege["RETURN"] += subj_op_counts[subject]["RETURN"] * subj_sizes[return_domain]
                
            else:
                print(f"Subject {return_domain} not found")

        for read_descriptor in principal['can_read']:
            for obj_domain in read_descriptor['objects']:
                if obj_domain in obj_sizes:
                    privilege["READ"] += subj_op_counts[subject]["READ"] * obj_sizes[obj_domain]
                else:
                    print(f"Object {obj_domain} not found")
                    
        for write_descriptor in principal['can_write']:
            for obj_domain in write_descriptor['objects']:
                if obj_domain in obj_sizes:
                    privilege["WRITE"] += subj_op_counts[subject]["WRITE"] * obj_sizes[obj_domain]
                else:
                    print(f"Object {obj_domain} not found")

    # Now calculate monolithic privilege
    mono_priv = {}
    for op in ops:
        mono_priv[op] = 0

    all_code_size = sum(subj_sizes.values())
    all_data_size = sum(obj_sizes.values())
    
    total_read_instrs = sum(s["READ"] for s in subj_op_counts.values())
    total_write_instrs = sum(s["WRITE"] for s in subj_op_counts.values())
    total_call_instrs = sum(s["CALL"] for s in subj_op_counts.values())
    total_return_instrs = sum(s["RETURN"] for s in subj_op_counts.values())

    mono_priv["CALL"] = total_call_instrs * all_code_size
    mono_priv["RETURN"] = total_return_instrs * all_code_size
    mono_priv["READ"] = total_read_instrs * all_data_size
    mono_priv["WRITE"] = total_write_instrs * all_data_size

    PSR = calculate_PSR(privilege, mono_priv)

    print("PSR: ")
    for key in PSR:
        print(f"{key}\t{PSR[key]}")

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

    if len(sys.argv) < 2:
        print('Usage: python3 calculate_privilege.py <trace path>')
        exit(0)

    compfile = sys.argv[1]

    # Open the file
    try:
        f = open(compfile, 'r')
    except Exception as e:
        print("Unable to open file " + sys.argv[1])

    # Parse as yaml
    try:
        c = yaml.safe_load(f)
    except yaml.YAMLError as e:
        print("Error parsing yaml file: " + policyfile)
    
    # Calculate privileges on it
    calculate_privilege(c)
