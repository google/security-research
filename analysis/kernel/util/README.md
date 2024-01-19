# Description

This repository contains CodeQL utility queries designed to analyze the Linux kernel source code.

## Queries

### syscalls.ql 

Identifies system calls within the Linux kernel codebase and extracts relevant parameters for each syscall.

#### Run query
```
codeql query run $query -d=$database --threads=$(nproc) -o output.bqrs
```

#### Export results
```
codeql bqrs decode output.bqrs --format=csv > syscalls.csv 
```

Note: in the results directory you will find some results of a previous run.
