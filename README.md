Syntia is a program synthesis based framework for deobfuscation. It uses instruction traces as an blackbox oracle to produce random input and output pairs. From these I/O pairs, the synthesizer learns the code's underlying semantic. 

The framework is based on our [paper](https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-blazytko.pdf):

```
@inproceedings{blazytko2017syntia,
    author = {Blazytko, Tim and Contag, Moritz and Aschermann, Cornelius and Holz, Thorsten},
    title = {{Syntia: Synthesizing the Semantics of Obfuscated Code}},
    year = {2017},
    booktitle = {USENIX Security Symposium} 
}
```


# Usage

The `scripts` demonstrate the usage of the framework.

## Symbolic execution

To symbolically execute an instruction trace of an obfuscated expressions, use

```
python2 scripts/miasm_se_oracle.py samples/tigress_mba_trace.bin x86_64

```

In this example, the expression is obfuscated via Mixed Boolean-Arithmetic (MBA). The final result is stored in `EAX`.

## Random Sampling

`random_sampling.py` generates random I/O pairs for a piece of code. Its output is a JSON file. To sample 20 times, use 

```
python2 scripts/random_sampling samples/ tigress_mba_trace.bin x86_64 20 mba_sampling.json
```

It can be specified if memory and/or register locations are inputs/outputs.

## Program Synthesis for Obfuscated Code

`sample_synthesis` uses the I/O samples and synthesizes the semantics of each input. It is possible to synthesize only specific outputs (e.g., `EAX`):

```
{
 "output": {
     "name": "EAX", 
     "number": 0, 
     "size": 32
 }, 
 "top_non_terminal": {
     "expression": {
         "infix": "((u32 * u32) + (u32 * 1))"
     }, 
     "reward": 1.0
 }, 
 "top_terminal": {
     "expression": {
         "infix": "((mem_0x2 * mem_0x0) + (mem_0x4 * 1))"
     }, 
     "reward": 1.0
 }, 
 "successful": "yes", 
 "result": {
     "final_expression": {
         "infix": "((mem_0x2 * mem_0x0) + (mem_0x4 * 1))", 
         "simplified": "((mem_0x2 * mem_0x0) + (mem_0x4 * 1))"
     }
 }
}
```

The MBA-obfuscated expressions is equivalent to `(mem_0x2 * mem_0x0) + mem_0x4`, where `mem_i` corresponds to the i-th memory read.

## General Program Synthesis

`mcts_synthesis_multi_core.py` shows a basic usage of the synthesis algorithm. It can be used to test the synthesis of different expressions (which can be defined in `oracle`). Furthermore, it allows to test the synthesis behavior for different configuration parameters.

# Structure

Syntia's code is structured in three parts: symbolic execution of obfuscated code, generating I/O pairs from binary code and the program synthesizer.

## symbolic_execution

A wrapper around Miasm's symbolic execution engine. We use it to symbolically execute pieces of obfuscated code.

## kadabra

Kadabra is our a blanked execution framework which is built on top of Unicorn Engine. Besides others, it supports instruction tracing, enforcing execution paths and tracing memory modifications. 

## assembly_oracle
The assembly oracle utilizes binary code as a black box and generates I/O pairs for the synthesizer. It is built upon Kadabra.

## mcts

It is the the core of Syntia: Monte Carlo Tree Search based program synthesis. Given I/O pairs from the assembly oracle, the synthesizer finds semantically equivalent non-obfuscated code.

## utils

Provides basic functionality that is used across the different subprojects. Furthermore, it contains some code that illustrates the parsing and usage of the random sampling results for program synthesis.
.....


# Setup

## Dependencies

The file `install_deps.sh` provides the build process of our dependencies. Major pars of our framework can be used without all dependencies. In particular, we use

- [Capstone disassembly framework](https://github.com/aquynh/capstone)( (used by our assembly oracle)
- [Unicorn CPU emulator framework](https://github.com/unicorn-engine/unicorn) (used by Kadabra and our assembly oracle)
- [Z3 theorem prover + python bindings](https://github.com/Z3Prover/z3) (used by our synthesizer for expression simplification)
- [Miasm](https://github.com/cea-sec/miasm) (for symbolic execution)

## Docker

We provide a Docker container that contains all dependencies (but not Syntia itself). To build it, use the following commands:

```
# build docker container
docker build -t <name of container> <directory with docker file>

# run docker container interactively
docker run -it <container name> /bin/bash
```

The containers superuser password is `root`.

# Contact

tim DOT blazytko AT rub DOT de