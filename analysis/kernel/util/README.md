# Description

This repository contains CodeQL utility queries designed to analyze the Linux kernel source code.

## Queries

### syscalls.ql 

Identifies system calls within the Linux kernel codebase and extracts relevant parameters for each syscall.

### Functions.ql 

Identifies within the Linux kernel codebase and extracts their file, start-line and end-line. 

### Fields.ql 

Identifies fields within the Linux kernel codebase and extracts their parent struct, their name, their type, their offset and if they might be interesting. 

#### Run query
```
codeql query run $query -d=$database --threads=$(nproc) -o output.bqrs
```

#### Export results
```
codeql bqrs decode output.bqrs --format=csv > syscalls.csv 
```

Note: in the results directory you will find some results of a previous run.
