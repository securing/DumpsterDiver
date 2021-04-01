#!/usr/bin/env python3

import advancedSearch
import core
import os
import sys
import argparse
from termcolor import colored
import colorama
colorama.init()


#Borrowed from https://bitbucket.org/ruamel/std.argparse
class SmartFormatter(argparse.HelpFormatter):
    def _split_lines(self, text, width):
        if text.startswith('R|'):
            return text[2:].splitlines()  
        # this is the RawTextHelpFormatter._split_lines
        return argparse.HelpFormatter._split_lines(self, text, width)


def opening():
    title = """

       ___                          __             ___   _                
      / _ \ __ __ __ _   ___   ___ / /_ ___  ____ / _ \ (_)_  __ ___  ____
     / // // // //  ' \ / _ \ (_-</ __// -_)/ __// // // /| |/ // -_)/ __/
    /____/ \_,_//_/_/_// .__//___/\__/ \__//_/  /____//_/ |___/ \__//_/   
                      /_/                                                 
            """
    creds = "                                                       #Coded by @Rzepsky"
    
    print(colored(title, 'magenta') )
    print(colored(creds, 'red') )
    print()
    print()


if __name__ == '__main__':

    opening()
    parser = argparse.ArgumentParser(formatter_class=SmartFormatter)
    basic = parser.add_argument_group('BASIC USAGE')
    configuration = parser.add_argument_group('CONFIGURATION')
    basic.add_argument('-p', dest='local_path', required=True, 
        help="path to the folder containing files to be analyzed")
    basic.add_argument('-r', '--remove', action='store_true', 
        help="when this flag is set, then files which don't contain"
             + " any secret will be removed.")
    basic.add_argument('-a', '--advance', action='store_true', 
        help="when this flag is set, then all files will be additionally "
             + "analyzed using rules specified in 'rules.yaml' file.")
    basic.add_argument('-s', '--secret', action='store_true', 
        help="when this flag is set, then all files will be additionally "
             + "analyzed in search of hardcoded passwords.")    
    basic.add_argument('-o', dest='outfile', default='results.json', 
        help="output file in JSON format.")   

    configuration.add_argument('--min-key', dest='min_key', type=int, 
        help="specifies the minimum key length to be analyzed (default is 20).")
    configuration.add_argument('--max-key', dest='max_key', action='store', 
        type=int, help="specifies the maximum key length to be analyzed (default is 80).")
    configuration.add_argument('--entropy', action='store', type=float,
        help="specifies the edge of high entropy (default is 4.3).")
    configuration.add_argument('--min-pass', dest='min_pass', action='store', 
        type=int, help="specifies the minimum password length to be analyzed"
                       + " (default is 8). Requires adding '-s' flag to the "
                       + "syntax.")
    configuration.add_argument('--max-pass', dest='max_pass', action='store', 
        type=int, help="specifies the maximum password length to be analyzed"
                       + " (default is 12). Requires adding '-s' flag to the "
                       + "syntax.")
    configuration.add_argument('--pass-complex', dest='password_complexity', 
        type=int, choices=range(1,10), help="specifies the edge of password "
                       + "complexity between 1 (trivial passwords) to 9 (very "
                       + "complex passwords) (default is 8). Requires adding "
                       + "'-s' flag to the syntax.")
    configuration.add_argument('--exclude-files', dest='exclude_files', action='store', 
        nargs='+', help="specifies file names or extensions which shouldn't be analyzed. "
                        + "File extension should contain '.' character (e.g. '.pdf'). "
                        + "Multiple file names and extensions should be separated by space.")
    configuration.add_argument('--bad-expressions', dest='bad_expressions', 
        action='store', nargs='+', help="specifies bad expressions - if the DumpsterDiver "
                        + "find such expression in a file, then this file won't be analyzed. "
                        + "Multiple bad expressions should be separated by space. ")

    try:
        arguments = parser.parse_args()

        if arguments.local_path:

            if os.path.isdir(arguments.local_path) or os.path.isfile(arguments.local_path):
                arguments.local_path = os.path.abspath(arguments.local_path)
                
            else:
                print("The specified path '" + arguments.local_path 
                      + "' doesn't exist.")
                sys.exit()

        core.start_the_hunt(arguments)
            
    except IOError as msg:
        parser.error(str(msg))


