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

# Reduced Version

This fork is a version of Syntia that is reduced to its MCTS core. It can be used to play with expression synthesis and different synthesis configurations.

To play around, the `scripts/io_map.py` allows to define I/O relationships; the synthesizer then tries to find an corresponding expression.

```
# example I/O map
in_out_map = {
    (1, 1, 1): 2,
    (1, 2, 3): 3,
}
```

# Contact

tim AT blazytko DOT to
