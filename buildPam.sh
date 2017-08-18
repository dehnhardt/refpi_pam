#!/bin/bash

gcc -fPIC -fno-stack-protector -c src/refpi_pam.c

sudo ld -x --shared -o /lib/security/refpi_pam.so refpi_pam.o

rm refpi_pam.o
