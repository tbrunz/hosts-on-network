# hosts-on-network
Scan a network for hosts, identifying which are known & which are unknown

This app is a Lua script (launchable from the CLI) that will scan a designated
network and compile a list of MAC addresses for hosts that it finds.

The script uses `nmap` to run a simple ping test (`-sP`) to locate hosts.
However, `nmap` has a pathology: The final record is always the NIC of the
host performing the scan, but its record format is different from the other
records.  Among the problems with the host record is that it includes only
the host IP number, but not its MAC address or other information.

Consequently, additional functions are defined that "reverse engineer" the
host IP address to determine the MAC address of the NIC used for the subnet
of interest (as there may be more than one NIC on the host, which itself
could be dual-homed) and the vendor of the host platform.  

With this additional information determined, the table of found hosts can be
processed using a table of known hosts that contains a MAC address and a
recognizable description of each device.

Two resulting lists are then formed: One for host info corresponding to hosts
that are known and one for hosts that are not recognized.  A report is then
produced and dumped to `stdout`
