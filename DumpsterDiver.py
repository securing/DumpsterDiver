#!/bin/env python

import core
import os
import sys
from argparse import ArgumentParser
from termcolor import colored


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
    parser = ArgumentParser()
    parser.add_argument("-p", dest="local_path", required=True, help="path to the folder containing files to be analyzed")
    parser.add_argument("-r", "--remove", action='store_true', default=False, help="when this flag is set, then files which don't contain any secret will be removed.")
    parser.add_argument("-a", "--advance", action='store_true', default=False, help="when this flag is set, then all files will be additionally analyzed using rules specified in 'rules.yaml' file.")    

    try:
        arguments = parser.parse_args()
        core.REMOVE_FLAG = arguments.remove
        core.ADVANCED_SEARCH = arguments.advance

        if arguments.local_path:

            if os.path.isdir(arguments.local_path):
                core.PATH = os.path.abspath(arguments.local_path)
                
            else:
                print("The specified path '" + arguments.local_path + "' doesn't exist.")
                sys.exit()

        core.start_the_hunt()

            
    except IOError as msg:
        parser.error(str(msg))


