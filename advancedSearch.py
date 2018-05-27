#!/bin/env python

import yaml
import os
import fnmatch
import core
from termcolor import colored

class AdvancedSearch(object):
    def __init__(self):
        self._RULES = yaml.safe_load(open('rules.yaml'))
        self._FILETYPE = self._RULES['filetype']
        self._FILETYPE_WEIGHT = self._RULES['filetype_weight']
        self._GREP_WORDS = self._RULES['grep_words']
        self._GREP_WORD_OCCURRENCE = self._RULES['grep_word_occurrence']
        self._GREP_WORDS_WEIGHT = self._RULES['grep_words_weight']
        self._OCCURRANCE_COUNTER = 0
        self._FINAL_WEIGHT = 0
        self._EXIST = True

    def grepper(self, word):
        for search_expression in self._GREP_WORDS:

            if fnmatch.fnmatch(word, search_expression):
                self._OCCURRANCE_COUNTER += 1

        if self._OCCURRANCE_COUNTER >= self._GREP_WORD_OCCURRENCE:
            self._FINAL_WEIGHT += self._GREP_WORDS_WEIGHT


    def filetype_check(self, file):
        file_name, extension = os.path.splitext(file)
        for ext in self._FILETYPE:
            
            if fnmatch.fnmatch(extension, ext):
                self._FINAL_WEIGHT += self._FILETYPE_WEIGHT  

    def final(self, file):
        if self._FINAL_WEIGHT >= 10:
            print(colored("INTERESTING FILE HAS BEEN FOUND!!!", 'cyan'))
            print(colored("The rule defined in 'rules.yaml' file has been triggerred. Checkout the file " + file, 'cyan'))
            interesting_file = True
            core.log('the rule defined in "rules.yaml" file has been triggerred while analyzing file ' + file, 'info')      
            return True
        else:
            return False