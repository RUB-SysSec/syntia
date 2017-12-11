FROM debian
MAINTAINER Tim Blazytko <tim.blazytko@rub.de>

RUN apt-get update -y && \
    # general dependencies
    apt-get install -y wget less vim git htop build-essential screen psmisc && \
    # specific dependencies
    apt-get install -y python-dev python-setuptools ipython python-pip libglib2.0-dev libffi-dev && \
    pip install orderedset && \

    # unicorn
    cd /usr/src && \
    git clone https://github.com/unicorn-engine/unicorn.git && \
    cd /usr/src/unicorn && \
    ./make.sh && ./make.sh install && \
    cd /usr/src/unicorn/bindings/python && \
    make install && \

   # capstone
   cd /usr/src && \
   git clone https://github.com/aquynh/capstone.git && \
   cd /usr/src/capstone && \
   git checkout next && \
   make && \
   make install && \
   cd /usr/src/capstone/bindings/python && \
   make && \
   make install && \

   # miasm
   cd /usr/src && \
   git clone https://github.com/serpilliere/elfesteem.git elfesteem && \
   cd elfesteem && \
   python2 setup.py build && \
   python2 setup.py install && \
   cd .. && \
   git clone https://github.com/cea-sec/miasm.git && \
   cd miasm && \
   python2 setup.py build && \
   python2 setup.py install && \

   # z3
   cd /usr/src && \
   git clone https://github.com/Z3Prover/z3.git && \
   cd z3 && \
   python scripts/mk_make.py --python && \
   cd build && \
   make -j 5 && \
   make install && \

   # cleanup
   rm -rf /usr/src/*  && \
   rm -rf /var/cache/apt/archives/* && \
   
   # set root password to "root"
   echo "root:root" | chpasswd && \

   # add user
   adduser	 --disabled-password --gecos '' docker



USER docker
WORKDIR /home/docker