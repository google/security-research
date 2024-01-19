# Linux Kernel Analysis with CodeQL

This directory contains repositories focused on the security analysis of the Linux kernel using CodeQL.

## Available directories:

### util:

Description: Contains CodeQL queries for general-purpose analysis of the Linux kernel source code.
Example query: `syscalls.ql` to identify and extract system calls and their
parameters.

See the README within this repository for more details and instructions.

### heap-exploitation

Description: Contains CodeQL queries specifically designed to find patterns and objects relevant to heap exploitation in the Linux kernel.
Example query: `InterestingObjects.ql` to locate interesting heap objects.

See the README within this repository for more details and instructions.

## Prerequisites

CodeQL installation: Refer to the CodeQL documentation (https://codeql.github.com/docs/) for installation and setup.

CodeQL databases: You will need to create CodeQL databases representing the Linux kernel source code. Follow the guidelines in the documentation or within each repository's README.


