These scripts will configure the network interface in the server and client
containers, respectively, to simulate networking conditions such as delay,
jitter, packet loss etc using `tc netem`.

Keep the following points in mind:
 - tc normally applies to egress (i.e. outoing) traffic -- that is, traffic
   *leaving* an interface. Ingress traffic conditions can be simulated as well
   at the expense of some more complex setup (using an `fib` interface -- see
   tcingress.sh -- TODO)
 - You can use agent.py to ping the server either from the `pingclient`
   container or straight from the host. Consequently, if you apply e.g. tc netem
   delay to egress/ingress traffic inside the `pingserver` container, the
   measurement reports via agent.py will be affected on both host and the
   `pingclient` container. If you only want the `pingclient` container to be
   affected (i.e. simulate adverse network conditions only for `pingclient`)
   but not the host, then you should apply the delay, pktloss etc inside the
   `pinclient` container, *not* the `pingserver` container.


