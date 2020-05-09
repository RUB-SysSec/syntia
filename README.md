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

# Branch

This branch is a reduced version that is only used for expression synthesis.

# Contact

tim DOT blazytko AT rub DOT de
