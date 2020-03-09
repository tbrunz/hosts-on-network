#! /usr/bin/env lua

--
-- Read in the local network's database of known hosts
--
NetworkDatabase = require "mac-addresses"


--
-- Function to query the OS to get this platform's NIC data
--
ShellHandler = { }

function ShellHandler:parseShellCmd ( shellCommand, Results )

    local tempFile = "/tmp/lua-shell-cmd"
    self.result = Results

    if os.execute( shellCommand.." > "..tempFile )
        and io.input( tempFile ) then

        for line in io.lines() do
            if self:findMatch( line ) then break end
        end

        io.input():close()
        os.remove( tempFile )

        return self.result
    end

    error( "Execution of OS command '"..shellCommand.."' failed!" )
end


--
-- Function to query the OS to get this platform's vendor
--
function myVendor ( )

    function ShellHandler:findMatch( line )
            local vendor = line:match( "vendor: ([^]]+)" )

            if vendor then
                self.result = vendor
                return true
            end
        end

    return ShellHandler:parseShellCmd( "sudo lshw" )
end


--
-- Function to query the OS to get this platform's NIC data
--
function myNICs ( )
    local MyNICs = { }

    function ShellHandler:findMatch( line )
            local interface, ipNumber = line:match( "(%w+)%s+UP%s+([^/]+)" )

            if interface then
                MyNICs[ #MyNICs+1 ] = { interface=interface, ipNumber=ipNumber }
            end
        end

    return ShellHandler:parseShellCmd( "ip -br addr", MyNICs )
end


--
-- Function to query the OS to get this platform's NICs' MAC addresses
--
function myMACs ( )
    local MyMACs = { }

    function ShellHandler:findMatch( line )
            local interface, macAddr = line:match( "%d+: (%w+):.+ether (%S+)" )

            if interface then
                MyMACs[ #MyMACs+1 ] =
                    { interface=interface, macAddr=macAddr:upper() }
            end
        end

    return ShellHandler:parseShellCmd( "ip -o -f link addr", MyMACs )
end


--
-- Function to query the OS to get hosts on the local network
--
function myLAN ( )
    local MyLAN = { }

    function ShellHandler:firstMatch( line )
            local ipNumber = line:match( "Nmap scan report for (%S+)" )

            if ipNumber then
                MyLAN[ #MyLAN+1 ] = { ipNumber=ipNumber }

                ShellHandler.findMatch = ShellHandler.secondMatch
            else
                if line:match( "Starting Nmap" ) then
                    return
                else
                    error( "Could not detect start of 'nmap' scan!" )
                end
            end
        end

    function ShellHandler:secondMatch( line )
            local status = line:match( "Host is (%w+)" )

            if status then
                MyLAN[ #MyLAN ].status=status

                ShellHandler.findMatch = ShellHandler.thirdMatch
            end
        end

    function ShellHandler:thirdMatch( line )
            local macAddr, vendor = line:match( "MAC Address: (%S+)%s+(.+)" )

            if macAddr then
                MyLAN[ #MyLAN ].macAddr=macAddr:upper()
                MyLAN[ #MyLAN ].vendor=vendor

                ShellHandler.findMatch = ShellHandler.firstMatch
            else
                if line:match( "Nmap done" ) then
                    return true
                else
                    error( "Could not detect end of 'nmap' scan!" )
                end
            end
        end

    subnet = NetworkDatabase.NetworkIPv4.subnet.."/"..
        tostring(NetworkDatabase.NetworkIPv4.CIDR)

    ShellHandler.findMatch = ShellHandler.firstMatch

    return ShellHandler:parseShellCmd( "sudo nmap -n -sP "..subnet, MyLAN )
end


--
-- Function to determine the MAC address of my NIC on my LAN
--
function getMyMacAddr ( myIPnumber )
    local myInterface, myMacAddr

    for _, NIC in ipairs( myNICs() ) do
        if NIC.ipNumber == myIPnumber then
            myInterface = NIC.interface
            break
        end
    end

    if not myInterface then
        error( "Cannot find my own network interface device!" )
    end

    for _, MAC in ipairs( myMACs() ) do
        if MAC.interface == myInterface then
            myMacAddr = MAC.macAddr
            break
        end
    end

    if not myMacAddr then
        error( "Cannot find my own network device's MAC address!" )
    end

    return myMacAddr
end


--
-- Function to get a table of all the devices detected on the network
--
function getNetworkDevices ( )

    MyLAN = myLAN()

    myIPnumber = MyLAN[ #MyLAN ].ipNumber
    myMacAddr = getMyMacAddr( myIPnumber )

    MyLAN[ #MyLAN ].macAddr = myMacAddr:upper()
    MyLAN[ #MyLAN ].vendor = "("..myVendor()..")"
end


--
-- Check a network host against a database of known hosts
--
function checkNetworkHost ( NetworkHost )

    for _, KnownHost in ipairs( NetworkDatabase.HostsByMAC ) do

        if NetworkHost.macAddr == KnownHost.macAddr then

            NetworkHost.description = KnownHost.description
            return true
        end
    end
end


--
-- Display a table of hosts
--
function displayHost( NetworkHost, hostType )
    local description = NetworkHost.description

    if not description then
        description = ""
    else
        description = "  descr: "..description
    end

    print( hostType.." host: IP number "..
        string.format("%-13s", tostring(NetworkHost.ipNumber))..
        "  MAC addr "..tostring(NetworkHost.macAddr)..
        --"  host is "..string.format("%-4s", tostring(NetworkHost.status))..
        description
        )
end


--
-- Gather the data, crunch it, and display the results
--
getNetworkDevices()

KnownHosts = { }
UnknownHosts = { }

for _, NetworkHost in ipairs( MyLAN ) do
    if checkNetworkHost( NetworkHost ) then
        KnownHosts[ #KnownHosts+1 ] = NetworkHost
    else
        UnknownHosts[ #UnknownHosts+1 ] = NetworkHost
    end
end

print()

for _, KnownHost in ipairs( KnownHosts ) do
    displayHost( KnownHost, "Known" )
end

print()

for _, UnknownHost in ipairs( UnknownHosts ) do
    displayHost( UnknownHost, "Unknown" )
end
