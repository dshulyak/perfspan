#!/bin/bpftrace

usdt:./$1:perfspan:enter
{
    printf("enter %lx %lx %s\n", arg0, arg1, str(arg2));
}

usdt:./$1:perfspan:exit
{   
    printf("exit %lx\n", arg0);
}
