#!/bin/bash

for i in {101..102};
do
    echo $i;
    ssh root@172.16.0.$i "ps aux | grep 'scanner' | grep -v 'grep'| awk '{ print \$2 }' | xargs kill -9";
done
