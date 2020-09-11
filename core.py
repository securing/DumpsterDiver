#!/usr/bin/env python3

import advancedSearch
import fnmatch
import json
import logging
import math
import mmap
import multiprocessing
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
EXCLUDED_FILES = CONFIG['excluded_files']
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
BAD_EXPRESSIONS = CONFIG['bad_expressions']

PASSWORD_REGEX = re.compile(r"['\">](.*?)['\"<]")

logging.basicConfig(filename=LOGFILE, level=logging.DEBUG,
                    format='%(asctime)s %(levelname)s %(name)s %(message)s')
logger = logging.getLogger(__name__)

def mp_handler(queue, result):
    # depending on your hardware the DumpsterDiver will use all available cores for
    # parallel processing

    p = multiprocessing.Pool(multiprocessing.cpu_count())
    while queue.qsize():
        p.apply_async(worker, (queue,result,))
    queue.join()


def worker(queue, result):
    _file = queue.get()
    analyze_file(_file, result)
    queue.task_done()


def analyze_file(_file, result):
    try:
        if BAD_EXPRESSIONS:
            if bad_expression_verifier(_file):
                logger.info("Bad expression has been found in a " + _file 
                    + " file. Skipping further analysis.")
                return

        entropy_found = False
        rule_triggerred = False

        if ADVANCED_SEARCH:
            additional_checks = advancedSearch.AdvancedSearch()
            additional_checks.filetype_check(_file)

            for word in get_all_strings_from_file(_file):
                additional_checks.grepper(word)
                if is_base64_with_correct_length(word, MIN_KEY_LENGTH, MAX_KEY_LENGTH):
                    if found_high_entropy(_file, word, result):
                        entropy_found = True

            if additional_checks.final(_file):
                data = {"Finding": "Advanced rule triggerred", "File": _file,
                        "Details": {"filetype": additional_checks._FILETYPE,
                                    "filetype_weight": additional_checks._FILETYPE_WEIGHT,
                                    "grep_words": additional_checks._GREP_WORDS,
                                    "grep_word_occurrence": additional_checks._GREP_WORD_OCCURRENCE,
                                    "grep_words_weight": additional_checks._GREP_WORDS_WEIGHT}}
                result.put(data)
        
        for word in get_base64_strings_from_file(_file, MIN_KEY_LENGTH, MAX_KEY_LENGTH):
            if found_high_entropy(_file, word, result):
                entropy_found = True

        if PASSWORD_SEARCH:
            # have to read line by line instead of words
            try:
                with open(_file) as f:
                    for line in f:
                        for password in password_search(line):
                            print(colored("FOUND POTENTIAL PASSWORD!!!", 'yellow'))
                            print(colored("Potential password ", 'yellow') + colored(password[0], 'magenta')
                                    + colored(" has been found in file " + _file, 'yellow'))
                            data = {"Finding": "Password",
                                    "File": _file,
                                    "Details": {"Password complexity": password[1],
                                                "String": password[0]}}
                            result.put(data)
                            logger.info("potential password has been found in a file " + _file)

            except Exception as e:
                logger.error("while trying to open " + str(_file) + ". Details:\n" + str(e))

        if REMOVE_FLAG and not (entropy_found or rule_triggerred):
            remove_file(_file)

    except Exception as e:
        logger.error("while trying to analyze " + str(_file) + ". Details:\n" + str(e))


def found_high_entropy(_file, word, result):
    b64Entropy = shannon_entropy(word)

    if (b64Entropy > HIGH_ENTROPY_EDGE) and false_positive_filter(word):
        print(colored("FOUND HIGH ENTROPY!!!", 'green'))
        print(colored("The following string: ", 'green')
              + colored(word, 'magenta')
              + colored(" has been found in " + _file, 'green'))
        print()
        logger.info("high entropy has been found in a file " + _file)
        data = {"Finding": "High entropy", "File": _file,
                "Details": {"Entropy": b64Entropy,
                            "String": word}}
        result.put(data)
        return True
    return False


def get_base64_strings_from_file(_file, min_length, max_length):
    with open(_file, 'r') as open_file:
        word = ""
        while True:

            buf = open_file.read(1024)
            if not buf:
                if max_length >= len(word) >= min_length:
                    yield word
                break

            for ch in buf:
                if ch in BASE64_CHARS:
                    word += ch
                elif max_length >= len(word) >= min_length:
                    yield word
                    word = ""
                else:
                    word = ""


def get_all_strings_from_file(_file):
    with open(_file, 'r') as open_file:
        for line in open_file.readlines():
            for word in line.split():
                yield word


def is_base64_with_correct_length(word, min_length, max_length):
    for ch in word:
        if ch not in BASE64_CHARS:
            return False
    return max_length >= len(word) >= min_length


def file_reader(file_path, queue):
    if get_file_extension(file_path) in ARCHIVE_TYPES:
        extract_path = get_unique_extract_path()
        extract_archive(file_path, extract_path)
        folder_reader(extract_path, queue)
    else:
        queue.put(file_path)


def folder_reader(path, queue):
    try:
        for root, subfolder, files in os.walk(path):
            for filename in files:

                extension = get_file_extension(filename)
                _file = root + '/' + filename

                # check if it is archive
                if filename in EXCLUDED_FILES or extension in EXCLUDED_FILES:
                    # remove unnecessary files
                    if REMOVE_FLAG:
                        _file = root + '/' + filename
                        remove_file(_file)

                elif extension in ARCHIVE_TYPES:
                    archive = root + '/' + filename
                    extract_path = get_unique_extract_path()
                    extract_archive(archive, extract_path)
                    folder_reader(extract_path, queue)

                elif extension == '' and ('.git/objects/' in _file):
                    try:
                        with open(_file, 'rb') as f:
                            # reading 16 magic bits to recognize VAX COFF
                            if f.read(2) == b'x\x01':
                                decompressed = git_object_reader(_file)

                                if decompressed:
                                    queue.put(decompressed)

                    except Exception as e:
                        logger.error(e)

                else:
                    queue.put(_file)

    except Exception as e:
        logger.error(e)


def get_file_extension(filename):
    return os.path.splitext(filename)[1]


def get_unique_extract_path():
    return os.getcwd() + '/Extracted_files/' + str(time.time())


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
    queue = multiprocessing.Manager().Queue()
    result = multiprocessing.Manager().Queue()

    if os.path.isfile(PATH):
        file_reader(PATH, queue)
    else:
        folder_reader(PATH, queue)
    mp_handler(queue, result)
    save_output(result)


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

        return new_file

    except Exception as e:
        logger.error(e)


def save_output(result):
    try:
        data = []

        while not result.empty():
            data.append(result.get())

        with open(OUTFILE, 'w') as f:
            json.dump(data, f)

    except Exception as e:
        logger.error("while trying to write to " + str(OUTFILE) + " file. Details:\n" + str(e))


def password_search(line):
    try:
        potential_pass_list = re.findall(PASSWORD_REGEX, line)
        pass_list = []

        for string in potential_pass_list:
            if (not MIN_PASS_LENGTH <= len(string) <= MAX_PASS_LENGTH) or \
                any(ch.isspace() for ch in string):
                continue

            password_complexity = passwordmeter.test(string)[0]

            if password_complexity < PASSWORD_COMPLEXITY * 0.1:
                continue

            yield (string, password_complexity)

    except Exception as e:
        logger.error(e)


def false_positive_filter(word):
    try:
        return digit_verifier(word) and order_verifier(word)
    except Exception as e:
        logger.error(e)


def has_whitespace(string):
    for s in string:
        if s.isspace():
            return True
    return False


def digit_verifier(word):
    return any(char.isdigit() for char in word)


def order_verifier(word):
    return 'abcdefgh' not in word.lower()

def bad_expression_verifier(_file):
    try:

        with open(_file, 'rb', 0) as f, \
        mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as string_object:

            for search_expression in BAD_EXPRESSIONS:

                if string_object.find(search_expression.encode()) != -1:
                    return True          

    except Exception as e:
        logger.error("while trying to open " + str(_file) + " file. Details:\n" + str(e))

