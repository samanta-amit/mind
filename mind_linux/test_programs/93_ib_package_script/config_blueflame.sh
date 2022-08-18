#!/bin/bash
if [ $1 -eq 1 ]; then
    export MLX5_POST_SEND_PREFER_BF=1
    export MLX5_SHUT_UP_BF=0
    unset MLX5_SHUT_UP_BF
else
    export MLX5_POST_SEND_PREFER_BF=0
    export MLX5_SHUT_UP_BF=1
fi