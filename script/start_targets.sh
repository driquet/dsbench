#!/bin/bash

for i in {101..102};
do
    echo $i;
    ssh -f root@192.168.0.$i "python ~/dsbench/remote/target.py -i 192.168.0.$i &";
done
