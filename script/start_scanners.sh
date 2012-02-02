#!/bin/bash

for i in {101..102};
do
    echo $i;
    ssh -f root@172.16.0.$i "python ~/dsbench/remote/scanner.py -i 172.16.0.$i &";
done
