## ndiffports_lsrr
**This repository is now obsolete, support has been [added](https://github.com/multipath-tcp/mptcp/commit/ae4459f9d4d7a937b5f2f704f460a9a37a2b16ec) to upstream MPTCP**

A fork of the ndiffports path manager module from the Linux kernel implementation of [MPTCP](https://github.com/multipath-tcp/mptcp).

IPv4 sub-flows may be separately loose source routed.

Re-write of the original MPTCP LSRR patch by Luca Boccassi as a path manager module.

### Prerequisites
- Headers for a [patched MPTCP v0.88 kernel](https://github.com/bluca/mptcp/tree/mptcp_v0.88_binder_pm_duncan)
- System(s) running the above patched kernel

### Compile
	make
	
### Setup
	insmod mptcp_ndiffports_lsrr.ko
	sysctl -w net.mptcp.mptcp_path_manager=ndiffports_lsrr
	# Number of flows, should be n+1 where n is the number of routes
	sysctl -w net.mptcp.mptcp_ndiffports_lsrr_ports=3
	# - separated list of , separated lists representing nodes to route via
	sysctl -w net.mptcp.mptcp_ndiffports_lsrr_gateways=192.168.1.1,10.0.1.1-192.168.1.1,10.0.2.1
