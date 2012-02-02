#!/bin/bash

for i in {101..102};
do
    echo $i;
    ssh root@192.168.0.$i "ps aux | grep 'target' | grep -v 'grep'| awk '{ print \$2 }' | xargs kill -9";
done
