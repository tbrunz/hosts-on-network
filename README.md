# hosts-on-network
### Scan a network for hosts, identifying which are known & which are unknown

This app is a Lua script (runs in Lua 5.1, 5.2, and 5.3; not tested with 5.4 
yet) that is launchable from the CLI that will scan a designated network and 
compile a list of MAC addresses for hosts that it finds.

It was written for Linux (but can probably be adapted for Mac without much 
work; Windows? Well, it runs in a VM).

#### NOTE: This script uses `nmap` to scan networks.  
> _While this script has been coded to run a simple ping test (`-sP`) to locate 
hosts, it is **not** intended for use on your employer's network!  Many 
companies do not take kindly to anyone other than authorized IT personnel 
running port scans on their networks.  This script is intended for your home 
networks and private lab/office networks, i.e., networks that are under **your** 
control and authorization.  Do **not** attempt to run this or any other 
scanning tools on your employer's network without their knowledge and consent!_

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

### Prerequisites
You'll need a Linux system with Lua installed (any version > 5.0).  While 
you probably want/have Luarocks, this script doesn't require any 'rocks'.
I.e., you don't need `luafilesystem` or `luasocket` installed.

You'll need to have `nmap` installed, too.  To run the script, you'll 
need `sudo` privileges, since `nmap` needs to be run as superuser in 
order to report the MAC addresses of hosts it finds.

## How to use hosts-on-network
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
sudo [lua] nethosts.lua
```

It may request your password for `sudo` authorization, since the script 
runs`nmap` in a shell to locate hosts on your network.  Why does `nmap` 
need `sudo` authorization?  Because without it, `nmap` will not return MAC 
addresses, and without MAC addresses, the script cannot make positive 
identifications of your known hosts.

After running for a few seconds, you should get a report in your terminal
similar to this:
```
Subnet 'My home LAN': 
Known host: IP number 192.168.1.1    MAC addr 44:55:EE:FF:66:77   descr: My home Wifi router
Known host: IP number 192.168.1.10   MAC addr AA:BB:01:02:CC:DD   descr: My laptop's Wifi

No Unknown hosts found.
```

Or, if there are 'unknown' hosts detected, you'll get a report similar 
to this:
```
Subnet 'My home LAN': 
Known host: IP number 192.168.1.1    MAC addr 44:55:EE:FF:66:77   descr: My home Wifi router
Known host: IP number 192.168.1.10   MAC addr AA:BB:01:02:CC:DD   descr: My laptop's Wifi

Subnet 'My home LAN': 
Unknown host: IP number 192.168.1.199  MAC addr 00:01:FF:EE:05:06 
```

If the script seems to be taking too long to respond, press `Ctrl-C` and 
check `mac-addresses.lua` to see if you're trying to scan an unreachable 
network.  `nmap` will hang on scanning unreachable networks, and this will 
make it appear that the Lua script is hanging.  (You can test this by 
running the the `nmap` command directly; it will be displayed in your 
terminal as part of the Lua stack trace if you `Ctrl-C` out of it.)

If there are 'unknown' hosts listed, step 3 is to track them down and 
determine what they are.  If you weren't able to enter the information 
for some of your known hosts earlier, then it's likely that some of the 
unknown hosts listed are those devices.  In this case, copy their data 
into `mac-addresses.lua`, and run again.  This time they should show up 
in the 'known host' report list.

Of course, the purpose of this script is to find hosts on your network 
that are truly 'unknown' and don't belong there!

Note that you can 'tune' the strategy used to find hosts on your network 
by changing the arguments passed to `nmap` on line 309.  Currently, the 
code uses a simple 'ping scan' (`nmap -n -sP <subnet>`), but other more 
complicated/thorough scans can be performed, some of which would take a 
lot more time to complete, but would be better at finding hosts that 
_would prefer not to be found_.

Again, do **_not_** attempt to run this or any other scanning tools on 
your employer's network without their knowledge and consent!  

**You have been warned...**
