# Privilege Calculator
This repository contains a standalone privilege calculator that calculates privilege metrics for a given system and compartmentalization specification. It operates on compartmentalization specifications provided in the CPM-IF YAML file format (definition available [here](https://github.com/SEVER-PROTECT/CPM-Interchange-Format)).

## Privilege Model
The calculator computes a low-level, instruction and object accessibility based quantification of the privilege permitted by a compartmentalization scheme. It is based on the research papers [uSCOPE](https://www.seas.upenn.edu/~andre/pdf/uscope_raid2021.pdf) and [SCALPEL](https://dl.acm.org/doi/pdf/10.1145/3461673).

In short, one unit of privilege is defined as the ability for one instruction to perform one operation type on one byte of data. For definitions of terms like *Principal*, *Object* and *Subject Domain* see the [CPM IF Specification](https://github.com/SEVER-PROTECT/CPM-Interchange-Format).

The following equation shows how the privilege for one operation type is calculated:

<br>
<img src="img/priv_equation.png" width="70%">

Where:

*Op* is one of four operation types: read, write, call, and return.

*Principals* is the set of all Principals in the system.

*Objects* is the set of all Objects in the system.

*p.sd.instr_op* is the number of instructions of type *op* inside the Subject Domain belonging to the Principal *p*.

*o.size* is the size in bytes of Object O.

"if *p* can perform *op* on *o*" is defined by a given compartmentalization specification that returns true or false for all triples *(Subject, Operation, Object)* thus defining the allowed permissions of the Compartmentalization.

## Example

### Simple Compartmentalization
To illustrate, we show the calculation for a small example. In this example, there are three functions F1, F2, F3. There are two primitive data entities O1 and O2. F1 and F2 are grouped together into a Subject Domain (SD1) and F3 is alone in SD2. O1 and O2 are each in their own Object Domains, OD1 and OD2. The sizes and number of instructions belonging to each object and function are shown in the diagram below. For simplicity, we assume an empty context and each SD and OD corresponds to a single Principal or Object. Arrows indicate allowed permissions of the labeled operation type.

This compartmentalization scheme represented in the CPM-IF YAML notation can be found at [example.yaml](example.yaml).

```mermaid
graph LR

%% SD1
subgraph SD1[SD1]
  F1[**F1**<br>Size: 20<br>Reads: 3<br >Writes: 0<br>Calls: 2<br >Returns: 2]
  F2[**F2**<br>Size: 30<br>Reads: 4<br >Writes: 0<br>Calls: 0<br >Returns: 1]
end
style SD1 fill:transparent,stroke:black
style F1 fill:#bbffbb,stroke:transparent
style F2 fill:#bbffbb,stroke:transparent

%% SD2
subgraph SD2[SD2]
  F3[**F3**<br>Size: 16<br>Reads: 5<br >Writes: 3<br>Calls: 1<br >Returns: 1]
end
style SD2 fill:transparent,stroke:black
style F3 fill:#bbffbb,stroke:transparent

%% OD1
subgraph OD1[OD1]
  O1{{**O1**<br>Size: 10}}
end
style OD1 fill:transparent,stroke:black
style O1 fill:#ADD8E6,stroke:transparent

%% OD2
subgraph OD2[OD2]
  O2{{**O2**<br>Size: 20}}
end
style OD2 fill:transparent,stroke:black
style O2 fill:#ADD8E6,stroke:transparent

%% Edges:
SD1 --> |call| SD2
SD2 --> |return| SD1
SD1 --> |read| OD1
SD2 --> |read| OD1
SD2 --> |write| OD2
```
### Calculating Privilege of Compartmentalization
Here we show how to calculate the privilege of the compartmentalization. 

*Principal SD1*

Read privilege: (3 + 4) x (10) = 70<br>
Write privilege: (0 + 0) x (0) = 0<br>
Call privilege: (2 + 0) x (20 + 30 + 16) = 132<br>
Return privilege: (2 + 1) x (20 + 30) = 150<br>

*Principal SD2*

Read privilege: (5) x (10) = 50<br>
Write privilege: (3) x (20) = 60<br>
Call privilege: (1) x (16) = 16<br>
Return privilege: (1) x (20 + 30 + 16) = 66<br>

*Total Privilege of Compartmentalization (SD1 + SD2)*:

Read: 70 + 50 = 120<br>
Write: 0 + 60 = 60<br>
Call: 132 + 16 = 148<br>
Return: 150 + 66 = 216<br>

### Calculating PSR
To calculate the PSR, we must first calculate the monolithic privilege. In the monolithic case, all instructions of each type can access all objects. We assume no W^X memory permissions, meaning it is possible to read/write code or call into data. There is a flag in the privilege calculator for assuming W^X.

*Monolithic Privilege*<br>
Read: (3 + 4 + 5) x (10 + 20 + 16 + 20 + 30) = 1,152<br>
Write: (0 + 0 + 3) x (10 + 20 + 16 + 20 + 30) = 288<br>
Call: (2 + 0 + 1) x (10 + 20 + 16 + 20 + 30) = 288<br>
Return: (1 + 2 + 1) x (10 + 20 + 16 + 20 + 30) = 384<br>

The Privilege Set Ratio (PSR) is defined as the privilege permitted by a compartmentalization divided by the monolithic privilege.

*PSR:*<br>
Read PSR: 120 / 1,152 = **0.1042**<br>
Write PSR: 60 / 288 = **0.2083**<br>
Call PSR: 148 / 288 = **0.5138**<br>
Return PSR: 216 / 384 = **0.5625**<br>
Total PSR: 544 / 2,112 = **0.2576**<br>

## Example with weight
The privilege calculator can optionally be provided with a weight file which can be used to augment or overwrite privileges on the code and objects in the system. For example, weight can be used to mark an object as very important (or as not important).  See [CPM IF Specification Appendix B](https://github.com/SEVER-PROTECT/CPM-Interchange-Format) for the weight file syntax.

To illustrate, consider applying a write weight of 10 to the object O2. Note that this is equivalent to settings its size to 200, but only for the write operation calculation.

Calculating the privileges with this weight gives us the following:

*Principal SD1 (same as before)*

Read privilege: (3 + 4) x (10) = 70<br>
Write privilege: (0 + 0) x (0) = 0<br>
Call privilege: (2 + 0) x (20 + 30 + 16) = 132<br>
Return privilege: (2 + 1) x (20 + 30) = 150<br>

*Principal SD2 (write changed)*

Read privilege: (5) x (10) = 50<br>
Write privilege: (3) x (20x10) = 600<br>
Call privilege: (1) x (16) = 16<br>
Return privilege: (1) x (20 + 30 + 16) = 66<br>

*Total Privilege of Compartmentalization (SD1 + SD2)*:

Read: 70 + 50 = 120<br>
Write: 0 + 600 = 600<br>
Call: 132 + 16 = 148<br>
Return: 150 + 66 = 216<br>

*Monolithic Privilege*<br>
Read: (3 + 4 + 5) x (10 + 20 + 16 + 20 + 30) = 1,152<br>
Write: (0 + 0 + 3) x (10 + 20x10 + 16 + 20 + 30) = 828<br>
Call: (2 + 0 + 1) x (10 + 20 + 16 + 20 + 30) = 288<br>
Return: (1 + 2 + 1) x (10 + 20 + 16 + 20 + 30) = 384<br>

*PSR:*<br>
Read PSR: 120 / 1,152 = **0.1042**<br>
Write PSR: 600 / 828 = **0.7246**<br>
Call PSR: 148 / 288 = **0.5138**<br>
Return PSR: 216 / 384 = **0.5625**<br>
Total PSR: 1,084 / 2,652 = **0.4087**<br>


## Setup and Usage

`calculate_privilege.py` requires the `pyyaml` and `argparse` packages. Install them with `pip3 install -r requirements.txt`.

Use with `python3 calculate_privilege.py <yaml> [--weight-file=file] [--wxorx | --no-wxorx]`

An input yaml in the CPM IF specification is required. The `--weight-file` flag is optional and may be used to modify privileges of individual elements of the system on per-operation type granularity. The `--wxorx` and `--nowxorx` can be used to set whether Write-XOR-Execute (W^X) memory permissions are assumed in monolithic privilege calculations.


When run on the included `example.yaml` file it produces the same results as our manual calculation:

```
$ python3 calculate_privilege.py example.yaml
PSR:
READ    0.3333333333333333
WRITE   0.06666666666666667
CALL    0.7474747474747475
RETURN  0.8181818181818182
TOTAL   0.44919786096256686
```

When run on the included `example.yaml` with setting the write weight of O2 to 10 using `weights.csv` it produces the same results as our manual calculation:

```

$ python3 calculate_privilege.py example.yaml --weight-file=weights.csv
PSR: 
READ	0.10416666666666667
WRITE	0.7246376811594203
CALL	0.5138888888888888
RETURN	0.5625
TOTAL	0.40874811463046756
```