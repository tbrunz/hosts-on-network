# hosts-on-network
### Scan a network for hosts, identifying which are known & which are unknown

This app is a Lua script (based on Lua 5.3 and launchable from the CLI) that 
will scan a designated network and compile a list of MAC addresses for hosts 
that it finds.

The script uses `nmap` to run a simple ping test (`-sP`) to locate hosts.

The address of the network to be scanned, along with a list of the known 
hosts, is kept in an adjacent "database" file.  This file is a "Lua data 
file"; i.e., it can be loaded via a Lua "require" statement as thought it 
were a code module.

The use of `nmap` has an issue, due to an unfortunate pathology: The final 
record that `nmap` includes in its report is always the NIC of the host 
performing the scan, but its record format differs from the other records. 
Among the problems with the host record is that it includes only the host 
IP number, but not its MAC address or other information.

To deal with this, additional functions are included to "reverse engineer" 
the host IP address to determine the MAC address of the NIC used for the 
subnet of interest (as there will be more than one NIC on a host that is 
dual-homed), as well as the vendor of the host platform.  

With this additional information determined, the table of found hosts is 
then processed using the table of known hosts, which contains host MAC 
addresses and descriptions of each device to make them recognizable.

Two resulting lists are created: One for host info corresponding to hosts
that are known and one for hosts that are not recognized.  A report is 
then produced and dumped to `stdout`

### How to use hosts-on-network
The first step is to enter the information you know for your network hosts 
in the `mac-addresses.lua` file.  This file has two sections; both must be 
completed.  The first is used to specify your network(s), more than one is 
allowed.  Currently only IPv4 is supported.  (IPv6 support is possible, but 
there are no plans to add it any time soon.)  The second section is used to 
specify your known hosts.  Both sections are arranged as Lua tables; the 
source code provides examples for each.  Note that the `vendor` field is 
optional.  

If you don't have all the info handy for all your hosts, you can omit them 
initially, then add them later, after you get the first report.

The next step is to run `nethosts.lua`, which is configured as a shell 
script (i.e., it has `#! /usr/bin/env lua` as its first line so that it 
will run if launched from the Linux command line).  So the commands would 
be:
```
cd <directory with nethosts.lua>
chmod +x nethosts.lua
./nethosts.lua
```

After a few seconds, you should get a report in your terminal:

