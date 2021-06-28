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
#PATH = './'
#OUTFILE = ''
ARCHIVE_TYPES = CONFIG['archive_types']
EXCLUDED_FILES = CONFIG['excluded_files']
#REMOVE_FLAG = False
LOGFILE = CONFIG['logfile']
MIN_KEY_LENGTH = CONFIG['min_key_length']
MAX_KEY_LENGTH = CONFIG['max_key_length']
HIGH_ENTROPY_EDGE = CONFIG['high_entropy_edge']
MIN_PASS_LENGTH = CONFIG['min_pass_length']
MAX_PASS_LENGTH = CONFIG['max_pass_length']
PASSWORD_COMPLEXITY = CONFIG['password_complexity']
BAD_EXPRESSIONS = CONFIG['bad_expressions']

PASSWORD_REGEX = re.compile(r"['\">](.*?)['\"<]")

logging.basicConfig(filename=LOGFILE, level=logging.DEBUG,
                    format='%(asctime)s %(levelname)s %(name)s %(message)s')
logger = logging.getLogger(__name__)

def mp_handler(queue, result, settings):
    # depending on your hardware the DumpsterDiver will use all available cores for
    # parallel processing

    p = multiprocessing.Pool(multiprocessing.cpu_count())
    while queue.qsize():
        p.apply_async(worker, (queue,result,settings))
    queue.join()


def worker(queue, result, settings):
    _file = queue.get()
    analyze_file(_file, result, settings)
    queue.task_done()


def analyze_file(_file, result, settings):
    try:
        bad_expressions = settings.bad_expressions if settings.bad_expressions else BAD_EXPRESSIONS
        if bad_expressions:
            if bad_expression_verifier(_file, bad_expressions):
                logger.info("Bad expression has been found in a " + _file 
                    + " file. Skipping further analysis.")
                return

        entropy_found = False
        rule_triggerred = False
        min_key = settings.min_key if settings.min_key else MIN_KEY_LENGTH
        max_key = settings.max_key if settings.max_key else MAX_KEY_LENGTH
        entropy = settings.entropy if settings.entropy else HIGH_ENTROPY_EDGE

        if settings.advance:
            additional_checks = advancedSearch.AdvancedSearch()
            additional_checks.filetype_check(_file)

            for word in get_all_strings_from_file(_file):
                additional_checks.grepper(word)
                if is_base64_with_correct_length(word, min_key, max_key):
                    if found_high_entropy(_file, word, result, entropy):
                        entropy_found = True

            if additional_checks.final(_file):
                data = {"Finding": "Advanced rule triggerred", "File": _file,
                        "Details": {"filetype": additional_checks._FILETYPE,
                                    "filetype_weight": additional_checks._FILETYPE_WEIGHT,
                                    "grep_words": additional_checks._GREP_WORDS,
                                    "grep_word_occurrence": additional_checks._GREP_WORD_OCCURRENCE,
                                    "grep_words_weight": additional_checks._GREP_WORDS_WEIGHT}}
                result.put(data)
        
        for word in get_base64_strings_from_file(_file, min_key, max_key):
            if found_high_entropy(_file, word, result, entropy):
                entropy_found = True

        if settings.secret:
            # have to read line by line instead of words

            try:
                with open(_file) as f:
                    for line in f:
                        for password in password_search(line, settings):
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

        if settings.remove and not (entropy_found or rule_triggerred):
            remove_file(_file)

    except Exception as e:
        logger.error("while trying to analyze " + str(_file) + ". Details:\n" + str(e))


def found_high_entropy(_file, word, result, entropy):
    b64Entropy = shannon_entropy(word)

    if (b64Entropy > entropy) and false_positive_filter(word):
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


def file_reader(queue, settings):
    if get_file_extension(settings.local_path) in ARCHIVE_TYPES:
        extract_path = get_unique_extract_path()
        extract_archive(settings.local_path, extract_path)
        folder_reader(extract_path, queue, settings)
    else:
        queue.put(settings.local_path)


def folder_reader(queue, settings):
    try:
        excluded_files = settings.exclude_files if settings.exclude_files else EXCLUDED_FILES

        for root, subfolder, files in os.walk(settings.local_path):
            for filename in files:

                extension = get_file_extension(filename)
                _file = root + '/' + filename

                # check if it is archive
                if filename in excluded_files or extension in excluded_files:
                    # remove unnecessary files
                    if settings.remove:
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
    try:
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

    except Exception as e:
        logger.error(e)


def start_the_hunt(settings):
    queue = multiprocessing.Manager().Queue()
    result = multiprocessing.Manager().Queue()

    if os.path.isfile(settings.local_path):
        file_reader(queue, settings)
    else:
        folder_reader(queue, settings)
    mp_handler(queue, result, settings)
    save_output(result, settings)


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


def save_output(result, settings):
    try:
        data = []

        while not result.empty():
            data.append(result.get())
            
        with open(settings.outfile, 'w') as f:
            json.dump(data, f)

    except Exception as e:
        logger.error("while trying to write to " + str(settings.outfile) + " file. Details:\n" + str(e))


def password_search(line, settings):
    try:
        potential_pass_list = re.findall(PASSWORD_REGEX, line)
        pass_list = []
        min_pass = settings.min_pass if settings.min_pass else MIN_PASS_LENGTH
        max_pass = settings.max_pass if settings.max_pass else MAX_PASS_LENGTH
        password_complexity_edge = settings.password_complexity if settings.password_complexity else PASSWORD_COMPLEXITY

        for string in potential_pass_list:
            if (not min_pass <= len(string) <= max_pass) or any(ch.isspace() for ch in string):
                continue

            password_complexity = passwordmeter.test(string)[0]

            if password_complexity < password_complexity_edge * 0.1:
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

def bad_expression_verifier(_file, bad_expressions):
    try:
        with open(_file, 'rb', 0) as f, \
        mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as string_object:

            for search_expression in bad_expressions:

                if string_object.find(search_expression.encode()) != -1:
                    return True          

    except Exception as e:
        logger.error("while trying to open " + str(_file) + " file. Details:\n" + str(e))

