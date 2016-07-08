from setuptools import setup

setup(
    name = 'hexag00n',
    description = "A collection of reverse engineering tools for the Qualcomm Digital Signal Proccesor (QDSP6)",
    url = 'https://github.com/programa-stic/hexag00n',
    version = '0.1',
    license = 'BSD 2-Clause',

    packages = ['hexagondisasm'],

    package_data = {
        'hexagondisasm': [
            'data/instruction_templates.pkl',
            # List of instruction templates needed by the disassembler.

            'data/factorial_example.elf',
            # Simple Hexagon binary (factorial example from the SDK) to test the disassembler.
        ],
    },

    install_requires = ['future', 'pyelftools'],

    zip_safe = False,
)
