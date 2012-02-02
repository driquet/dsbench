#!/bin/bash

for i in {101..102};
do
    ssh root@172.16.0.$i "rm -rf ~/dsbench && mkdir ~/dsbench";
    scp -r /data/git/exp/* root@172.16.0.$i:~/dsbench;
done

for i in {101..102};
do
    ssh root@192.168.0.$i "rm -rf ~/dsbench && mkdir ~/dsbench";
    scp -r /data/git/exp/* root@192.168.0.$i:~/dsbench;
done
