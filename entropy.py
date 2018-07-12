#!/bin/env python

import math
import sys

'''
This is a script which counts a character entropy in a single string.

Usage: entropy.py STRING

'''

BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="

def shannon_entropy(data):
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
        print("Error: " + str(e))


if __name__ == '__main__':

    if len(sys.argv) != 2:
        print("Exactly 1 argument is required.")
        print("Usage: entropy.py STRING")
        sys.exit()

    print("The entropy of a character in a string '" + sys.argv[1] + 
          "' is " + str(shannon_entropy(sys.argv[1])) + " bits")
