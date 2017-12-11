from setuptools import setup

setup(
    name='syntia',
    version='',
    packages=['syntia', 'syntia.mcts', 'syntia.utils', 'syntia.kadabra', 'syntia.kadabra.arch',
              'syntia.kadabra.arch.x86', 'syntia.kadabra.utils', 'syntia.kadabra.emulator', 'syntia.assembly_oracle',
              'syntia.symbolic_execution'],
    url='',
    license='GPLv2',
    author='Tim Blazytko',
    author_email='tim.blazytko@rub.de',
    description='A program synthesis framework for binary code deobfuscation'
)
