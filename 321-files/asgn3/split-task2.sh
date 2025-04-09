#!/bin/bash

for i in {08..09}
do
    python3 ./task2.py <(grep "\$$i" shadow) >> task2.out &
done

wait
