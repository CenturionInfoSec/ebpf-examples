# ebpf-examples

## hello_world.py

Trace `openat` syscall and print out the names of all files being opened.

## hello_world_pid_filter.py

`hello_world.py` with an additional PID filter.

## strace.py

General syscall tracing tool.

## hide_root_demo.py

Hide the presence of `su` files from an application. Bypasses the root
detection implemented by [UnCrackable-Level3.apk](https://github.com/OWASP/owasp-mstg/blob/master/Crackmes/Android/Level_03/UnCrackable-Level3.apk)

video: https://www.youtube.com/watch?v=eRftIoVs_Q8

[![CRESTCon Asia Presentation: 'EBPF - Android Reverse Engineering Superpowers' (Terry Chia, Centurion)](http://img.youtube.com/vi/eRftIoVs_Q8/0.jpg)](https://www.youtube.com/watch?v=eRftIoVs_Q8)
