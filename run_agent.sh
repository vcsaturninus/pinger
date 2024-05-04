#!/bin/bash

# should be 'server' or 'client'
mode="${mode:?}"
tc_scripts_dir="${tc_scripts_dir:?}"

if [[ "$mode" == "server" ]]; then
    echo "Running tc script ..."
    $tc_scripts_dir/tc_server_setup.sh
    echo "Running server agent ..."
    ./agent.py --${L4PROTO:?} server -p ${SERVER_PORT:?}

elif [[ "$mode" == "client" ]];then
    echo "Running tc script ..."
    $tc_scripts_dir/tc_client_setup.sh
    echo "Running client agent ..."
    ./agent.py --${L4PROTO:?} client -a ${SERVER_ADDR:?} -p ${SERVER_PORT:?}

else
    echo "Invalid mode: '$mode'"
fi
