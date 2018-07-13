#!/bin/env python

import advancedSearch
import fnmatch
import json
import logging
import multiprocessing
import math
import os
import passwordmeter
import re
import tarfile
import time
import yaml
import zipfile
import zlib
from termcolor import colored

CONFIG = yaml.safe_load(open('config.yaml'))
BASE64_CHARS = CONFIG['base64_chars']
PATH = './'
OUTFILE = ''
ARCHIVE_TYPES = CONFIG['archive_types']
EXCLUDED = CONFIG['excluded']
REMOVE_FLAG = False
ADVANCED_SEARCH = False
LOGFILE = CONFIG['logfile']
MIN_KEY_LENGTH = CONFIG['min_key_length']
MAX_KEY_LENGTH = CONFIG['max_key_length']
HIGH_ENTROPY_EDGE = CONFIG['high_entropy_edge']
PASSWORD_SEARCH = False
MIN_PASS_LENGTH = CONFIG['min_pass_length']
MAX_PASS_LENGTH = CONFIG['max_pass_length']
PASSWORD_COMPLEXITY = CONFIG['password_complexity']

logging.basicConfig(filename=LOGFILE, level=logging.DEBUG,
                    format='%(asctime)s %(levelname)s %(name)s %(message)s')
logger = logging.getLogger(__name__)

queue = multiprocessing.Manager().Queue()
result = multiprocessing.Manager().Queue()


def log(msg, log_type='error'):
    if log_type == 'error':
        logger.error(msg)
    elif log_type == 'info':
        logger.info(msg)


def mp_handler():
    # depending on your hardware the DumpsterDiver will use all available cores for
    # parallel processing

    p = multiprocessing.Pool(multiprocessing.cpu_count())
    while queue.qsize():
        result = p.apply_async(worker, )


def worker():
    _file = queue.get()
    analyzer(_file)
    queue.task_done()


def analyzer(_file):
    try:
        entropy_found = False
        rule_triggerred = False

        if ADVANCED_SEARCH:
            additional_checks = advancedSearch.AdvancedSearch()
            additional_checks.filetype_check(_file)

        for word in get_base64_strings_from_file(_file):

            b64Entropy = shannon_entropy(word)

            if (b64Entropy > HIGH_ENTROPY_EDGE) and false_positive_filter(word):
                print(colored("FOUND HIGH ENTROPY!!!", 'green'))
                print(colored("The following string: ", 'green')
                      + colored(word, 'magenta')
                      + colored(" has been found in "
                                + _file, 'green'))
                print()
                logger.info("high entropy has been found in a file " \
                            + _file)
                data = {"Finding": "High entropy", "File": _file,
                        "Details": {"Entropy": b64Entropy,
                                    "String": word}}
                result.put(data)
                entropy_found = True

            if ADVANCED_SEARCH:
                additional_checks.grepper(word)

        if ADVANCED_SEARCH:

            if additional_checks.final(_file):
                data = {"Finding": "Advanced rule triggerred", "File": _file,
                        "Details": {"filetype": additional_checks._FILETYPE,
                                    "filetype_weight": additional_checks._FILETYPE_WEIGHT,
                                    "grep_words": additional_checks._GREP_WORDS,
                                    "grep_word_occurrence": additional_checks._GREP_WORD_OCCURRENCE,
                                    "grep_words_weight": additional_checks._GREP_WORDS_WEIGHT}}
                result.put(data)

        if PASSWORD_SEARCH:
            # have to read line by line instead of words
            try:
                with open(_file) as f:
                    for line in f:
                        pass_list = password_search(line)
                        if pass_list:
                            for password in pass_list:
                                print(colored("FOUND POTENTIAL PASSWORD!!!", 'yellow'))
                                print(colored("Potential password ", 'yellow') + colored(password[0],
                                                                                         'magenta') + colored(
                                    " has been found in file " + _file, 'yellow'))
                                data = {"Finding": "Password", "File": _file,
                                        "Details": {"Password complexity": password[1], "String": password[0]}}
                                result.put(data)
                                logger.info("potential password has been found in a file " + _file)

            except Exception as e:
                logger.error("while trying to open " + str(_file) + ". Details:\n" + str(e))

        if REMOVE_FLAG and not (entropy_found or rule_triggerred):
            remove_file(_file)

    except Exception as e:
        logger.error("while trying to analyze "
                     + str(_file)
                     + ". Details:\n"
                     + str(e))


def get_base64_strings_from_file(_file):
    words = []
    with open(_file, 'r') as f:

        word = ""
        while True:

            buf = f.read(1024)

            if not buf:
                break

            for ch in buf:
                if ch in BASE64_CHARS:
                    word += ch
                elif MAX_KEY_LENGTH >= len(word) >= MIN_KEY_LENGTH:
                    words.append(word)
                    word = ""
                else:
                    word = ""

    return words


def folder_reader(path):
    try:
        for root, subfolder, files in os.walk(path):
            for filename in files:
                extension = os.path.splitext(filename)[1]
                _file = root + '/' + filename

                # check if it is archive
                if (extension or filename) in EXCLUDED:

                    # remove unnecesarry files
                    if REMOVE_FLAG:
                        _file = root + '/' + filename
                        remove_file(_file)

                elif extension in ARCHIVE_TYPES:
                    archive = root + '/' + filename
                    extract_path = os.getcwd() + '/Extracted_files/' + str(time.time())
                    extract_archive(archive, extract_path)
                    folder_reader(extract_path)

                elif extension == '' and ('.git/objects/' in _file):
                    try:
                        with open(_file, 'rb') as f:
                            # reading 16 magic bits to recognize VAX COFF
                            if f.read(2) == b'x\x01':
                                decompressed = git_object_reader(_file)

                                if decompressed:
                                    queue.put(decompressed)

                                f.close()

                    except Exception as e:
                        logger.error(e)

                else:
                    queue.put(_file)

    except Exception as e:
        logger.error(e)


def remove_file(_file):
    try:
        os.remove(_file)

    except Exception as e:
        logger.error(e)


def extract_archive(archive_file, path):
    if archive_file.endswith('.zip'):
        opener, mode = zipfile.ZipFile, 'r'

    elif archive_file.endswith('.tar.gz') or archive_file.endswith('.tgz'):
        opener, mode = tarfile.open, 'r:gz'

    elif archive_file.endswith('.tar.bz2') or archive_file.endswith('.tbz'):
        opener, mode = tarfile.open, 'r:bz2'

    else:
        logger.info("Extracting archive " + archive_file + " is not supported.")
        return

    with opener(archive_file, mode) as archive:
        archive.extractall(path=path)


def start_the_hunt():
    folder_reader(PATH)
    mp_handler()
    save_output()


def shannon_entropy(data):
    '''
    Borrowed from 
    http://blog.dkbza.org/2007/05/scanning-data-for-entropy-anomalies.html
    '''
    try:
        if not data:
            return 0

        entropy = 0
        for x in BASE64_CHARS:
            p_x = float(data.count(x)) / len(data)

            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)

        return entropy

    except Exception as e:
        logger.error(e)


def git_object_reader(_file):
    try:
        git_object = open(_file, 'rb').read()
        decompressed = zlib.decompress(git_object)
        new_file = _file + '_decompressed'

        with open(new_file, 'w') as decompressed_file:
            decompressed_file.write(str(decompressed))
            decompressed_file.close()
            return new_file

    except Exception as e:
        logger.error(e)


def save_output():
    try:
        data = []

        while not result.empty():
            data.append(result.get())

        with open(OUTFILE, 'w') as f:
            json.dump(data, f)

    except Exception as e:
        logger.error("while trying to write to "
                     + str(_file)
                     + " file. Details:\n"
                     + str(e))


def password_search(line):
    try:

        potential_pass_list = re.findall(r"['\">](.*?)['\"<]", line)
        pass_list = []

        for string in potential_pass_list:
            password_complexity = passwordmeter.test(string)[0]

            if (password_complexity >= PASSWORD_COMPLEXITY * 0.1) and \
                    (not re.search(r"\s", string)) and \
                    (MIN_PASS_LENGTH <= len(string) <= MAX_PASS_LENGTH):
                pass_list.append((string, password_complexity))

        return pass_list

    except Exception as e:
        logger.error(e)


def false_positive_filter(word):
    try:

        return all([digit_verifier(word),
                    order_verifier(word)])

    except Exception as e:
        logger.error(e)


def digit_verifier(word):
    return any(char.isdigit() for char in word)


def order_verifier(word):
    if 'abcdefgh' not in word.lower(): return True
