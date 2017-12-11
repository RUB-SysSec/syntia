#!/bin/bash
# unicorn
cd /tmp
git clone https://github.com/unicorn-engine/unicorn.git
cd /tmp/unicorn
./make.sh && ./make.sh install
cd /tmp/unicorn/bindings/python
make install

# capstone
cd /tmp
git clone https://github.com/aquynh/capstone.git
cd /tmp/capstone
git checkout next
make
make install
cd /tmp/capstone/bindings/python
make
make install

# miasm
cd /tmp
git clone https://github.com/serpilliere/elfesteem.git elfesteem
cd elfesteem
python2 setup.py build
python2 setup.py install
cd ..
git clone https://github.com/cea-sec/miasm.git
cd miasm
python2 setup.py build
python2 setup.py install

# z3
cd /tmp
git clone https://github.com/Z3Prover/z3.git
cd z3
python scripts/mk_make.py --python
cd build
make -j 5
make install
