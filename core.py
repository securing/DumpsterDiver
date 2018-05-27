#!/bin/env python

import yaml
import multiprocessing
import math
import os
import tarfile
import zipfile
import time
import fnmatch
import zlib
import logging
import advancedSearch
from termcolor import colored

CONFIG = yaml.safe_load(open('config.yaml'))
BASE64_CHARS = CONFIG['base64_chars']
PATH = './'
ARCHIVE_TYPES = CONFIG['archive_types']
EXCLUDED = CONFIG['excluded']
REMOVE_FLAG = False
ADVANCED_SEARCH = False
LOGFILE = CONFIG['logfile']
MIN_KEY_LENGTH = CONFIG['min_key_length']
MAX_KEY_LENGTH = CONFIG['max_key_length']

logging.basicConfig(filename=LOGFILE, level=logging.DEBUG, 
                    format='%(asctime)s %(levelname)s %(name)s %(message)s')
logger=logging.getLogger(__name__)

queue = multiprocessing.Manager().Queue()


def log(msg, log_type='error'):
    if log_type == 'error':
        logger.error(msg)
    elif log_type == 'info':
        logger.info(msg)

def mp_handler():
    jobs = []
    #depending on your hardware the DumpsterDiver will use all available cores
    for i in range(multiprocessing.cpu_count()):
        pro = [multiprocessing.Process(target=worker) for i in range(queue.qsize())]

    for p in pro:
        p.daemon = True
        p.start()
        jobs.append(p)
    
    for job in jobs:
        job.join() 
        job.terminate() 

def worker():
    file = queue.get()
    analyzer(file)
    queue.task_done()

def analyzer(file):
    try:
        entropy_found = False
        rule_triggerred = False

        if ADVANCED_SEARCH: 
            additional_checks = advancedSearch.AdvancedSearch()
            additional_checks.filetype_check(file)

        for word in file_reader(file):
            base64_strings = get_strings(word)

            for string in base64_strings:
                b64Entropy = shannon_entropy(string)

                if b64Entropy > 4.3:
                    #print(string + 'has entropy ' + str(b64Entropy))
                    print(colored('FOUND HIGH ENTROPY!!!', 'green'))
                    print(colored('The following string: ', 'green') + colored(string, 'magenta') + colored(' has been found in ' + file, 'green'))
                    logger.info('high entropy has been found in a file ' + file)
                    entropy_found = True

            if ADVANCED_SEARCH:
                additional_checks.grepper(word)

        if ADVANCED_SEARCH:
            rule_triggerred = additional_checks.final(file)

        if REMOVE_FLAG and not (entropy_found or rule_triggerred): remove_file(file)

    except Exception as e:
        logger.error('while trying to analyze ' + str(file) + '. Details:\n' + str(e))

def file_reader(file):
    try:
        with open(file, 'r', encoding = "ISO-8859-1") as f:
            while True:
                buf = f.read(1024)

                if not buf:
                    break

                while not str.isspace(buf[-1]):
                    ch = f.read(1)

                    if not ch:
                        break
                    buf += ch

                words = buf.split()

                for word in words:
                    yield word

            f.close()

    except Exception as e:
        print(colored('Cannot read '+file,'red'))
        log('while trying to read ' + str(file) + '. Details:\n' + str(e))

def folder_reader(path):
    try:
        for root, subfolder, files in os.walk(path):
            for filename in files:               
                extension = os.path.splitext(filename)[1]
                file = root + '/' + filename

                #check if it is archive
                if extension in EXCLUDED:

                    # remove unnecesarry files
                    if REMOVE_FLAG:
                        file = root + '/' + filename
                        remove_file(file)

                elif extension in ARCHIVE_TYPES:
                    archive = root + '/' + filename
                    folder_reader(extract_archive(archive))

                elif extension == '' and ('.git/objects/' in file):
                    try:
                        with open(file, 'rb') as f:
                            # reading 16 magic bits to recognize VAX COFF
                            if f.read(2) == b'x\x01':
                                decompressed = git_object_reader(file)

                                if decompressed:
                                    queue.put(decompressed)

                                f.close()

                    except Exception as e:
                        logger.error(e)

                else:
                    queue.put(file)

    except Exception as e:
        logger.error(e)

def remove_file(file):
    try:
        os.remove(file)

    except Exception as e: 
        logger.error(e)

def extract_archive(archive):
    try:
        if archive.endswith('.zip'):
            opener, mode = zipfile.ZipFile, 'r'

        elif archive.endswith('.tar.gz') or archive.endswith('.tgz'):
            opener, mode = tarfile.open, 'r:gz'

        elif archive.endswith('.tar.bz2') or archive.endswith('.tbz'):
            opener, mode = tarfile.open, 'r:bz2'

        else: 
            logger.info('Cannot open archive ' + archive)

        cwd = os.getcwd()
        #in case one archive contains another archive with the same name I used epoch time as the name for each extracted archive
        extracted_folder = cwd + '/Extracted_files/' + str(time.time())
        os.makedirs(extracted_folder)
        os.chdir(extracted_folder)
        file = opener(archive, mode)
        try: file.extractall()

        except Exception as e:
            print(colored('Cannot unpack ' + archive + ' archive', 'red'))
            logger.error(e)

        finally: file.close()

    except Exception as e:
        logger.error(e)

    finally:
        os.chdir(cwd)
        return extracted_folder

def start_the_hunt():
    folder_reader(PATH)    
    mp_handler()


def shannon_entropy(data):
    '''
    Borrowed from http://blog.dkbza.org/2007/05/scanning-data-for-entropy-anomalies.html
    '''
    try:
        if not data:
            return 0

        entropy = 0
        for x in BASE64_CHARS:
            p_x = float(data.count(x))/len(data)

            if p_x > 0:
                entropy += - p_x*math.log(p_x, 2)

        return entropy

    except Exception as e:
        logger.error(e)

def get_strings(word):
    try:
        count = 0
        letters = ''
        strings = []
        for char in word:

            if char in BASE64_CHARS:
                letters += char
                count += 1

            else:

                if MAX_KEY_LENGTH >= count >= MIN_KEY_LENGTH-1:
                    strings.append(letters)

                letters = ''
                count = 0

        if MAX_KEY_LENGTH >= count >= MIN_KEY_LENGTH-1:
            strings.append(letters)

        return strings

    except Exception as e:
        logger.error(e)

def git_object_reader(file):
    try:
        git_object = open(file, 'rb').read()
        decompressed = zlib.decompress(git_object)
        new_file = file + '_decompressed'

        with open(new_file, 'w') as decompressed_file:
            decompressed_file.write(str(decompressed))
            decompressed_file.close()
            return new_file
            
    except Exception as e:
        logger.error(e)


