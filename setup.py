import codecs
from setuptools import setup
from webssh._version import __version__ as version


starts = [u'### Preview', u'![Login]', u'![Terminal]']


def starts_with(line):
    for start in starts:
        if line.startswith(start):
            return True


with codecs.open('README.md', encoding='utf-8') as f:
    long_description = ''.join(line for line in f if not starts_with(line))


setup(
    name='webssh',
    version=version,
    description='Web based ssh client',
    long_description=long_description,
    author='Shengdun Hua',
    author_email='webmaster0115@gmail.com',
    url='https://github.com/huashengdun/webssh',
    packages=['webssh'],
    entry_points='''
    [console_scripts]
    wssh = webssh.main:main
    ''',
    license='MIT',
    classifiers=[
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
    ],
    install_requires=[
        'tornado>=4.5.0',
        'paramiko>=2.3.1',
    ],
)
