#!/bin/bash

find . -iname "*" | while read line 
do
   strings "$line"
done
