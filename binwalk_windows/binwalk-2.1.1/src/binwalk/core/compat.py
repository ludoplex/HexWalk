# All Python 2/3 compatibility stuffs go here.

from __future__ import print_function
import sys
import string

PY_MAJOR_VERSION = sys.version_info[0]

if PY_MAJOR_VERSION > 2:
    string.letters = string.ascii_letters

def iterator(dictionary):
    '''
    For cross compatibility between Python 2 and Python 3 dictionaries.
    '''
    return dictionary.items() if PY_MAJOR_VERSION > 2 else dictionary.iteritems()

def has_key(dictionary, key):
    '''
    For cross compatibility between Python 2 and Python 3 dictionaries.
    '''
    return key in dictionary if PY_MAJOR_VERSION > 2 else dictionary.has_key(key)

def get_keys(dictionary):
    '''
    For cross compatibility between Python 2 and Python 3 dictionaries.
    '''
    return list(dictionary.keys()) if PY_MAJOR_VERSION > 2 else dictionary.keys()

def str2bytes(string):
    '''
    For cross compatibility between Python 2 and Python 3 strings.
    '''
    if isinstance(string, type('')) and PY_MAJOR_VERSION > 2:
        return bytes(string, 'latin1')
    else:
        return string

def bytes2str(bs):
    '''
    For cross compatibility between Python 2 and Python 3 strings.
    '''
    if isinstance(bs, type(b'')) and PY_MAJOR_VERSION > 2:
        return bs.decode('latin1')
    else:
        return bs

def string_decode(string):
    '''
    For cross compatibility between Python 2 and Python 3 strings.
    '''
    if PY_MAJOR_VERSION > 2:
        return bytes(string, 'utf-8').decode('unicode_escape')
    else:
        return string.decode('string_escape')

def user_input(prompt=''):
    '''
    For getting raw user input in Python 2 and 3.
    '''
    return input(prompt) if PY_MAJOR_VERSION > 2 else raw_input(prompt)

