#!/bin/bash

gcc -fPIC -fno-stack-protector -c src/refpi_pam.c -lmount -Wall

sudo ld -x --shared -o /lib/security/pam_refpi.so refpi_pam.o -lmount

rm refpi_pam.o
