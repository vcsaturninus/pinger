#!/bin/bash

iface="eth0"
delay="2s"
tc qdisc add dev $iface root netem delay "$delay"
