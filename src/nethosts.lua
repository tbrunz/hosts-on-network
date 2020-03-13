#! /usr/bin/env lua

-------------------------------------------------------------------------------
--
-- Read in the local network's database of known hosts
--
NetworkDatabase = require "mac-addresses"


-------------------------------------------------------------------------------
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
            if line:match( "%w" ) and
                self:findMatch( line ) then break end
        end

        io.input():close()
        os.remove( tempFile )

        return self.result
    end

    error( "Execution of OS command '"..shellCommand.."' failed!" )
end


-------------------------------------------------------------------------------
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


-------------------------------------------------------------------------------
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


-------------------------------------------------------------------------------
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


-------------------------------------------------------------------------------
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


-------------------------------------------------------------------------------
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


-------------------------------------------------------------------------------
--
-- Function to get a table of all the devices detected on the network
--
function findHostsOnNetwork ( )

    MyLAN = myLAN()

    myIPnumber = MyLAN[ #MyLAN ].ipNumber
    myMacAddr = getMyMacAddr( myIPnumber )

    MyLAN[ #MyLAN ].macAddr = myMacAddr:upper()
    MyLAN[ #MyLAN ].vendor = "("..myVendor()..")"
end


-------------------------------------------------------------------------------
--
-- Gather the data, crunch it, and display the results
--
function sortHostsByFamiliarity ( HostsFoundOnNetwork )
    local DatabaseHostByMAC = { }

    -- Turn the NetworkDatabase sequence "inside out" to make an
    -- associative array of each known host keyed by its MAC addr.
    for _, DatabaseHost in ipairs( NetworkDatabase.HostsByMAC ) do
        --
        -- Extract the host's MAC address to use as the key to itself.
        DatabaseHostByMAC[ DatabaseHost.macAddr ] = DatabaseHost
    end

    -- Empty the two sorted tables, then fill them with sorted hosts.
    HostsThatAreKnown   = { }
    HostsThatAreUnknown = { }

    -- Sort the discovered hosts into two tables, depending on whether or
    -- not they are known hosts (listed in the 'NetworkDatabase' table).
    for _, ThisNetworkHost in ipairs( HostsFoundOnNetwork ) do
        --
        -- If this host is in the database, the lookup is non-nil.
        local DatabaseHost = DatabaseHostByMAC[ ThisNetworkHost.macAddr ]

        if DatabaseHost then
            -- If known, then set its description field from the DB.
            ThisNetworkHost.description = DatabaseHost.description

            HostsThatAreKnown[ #HostsThatAreKnown + 1 ] = ThisNetworkHost
        else
            -- We don't know this one, so we have no other description.
            HostsThatAreUnknown[ #HostsThatAreUnknown + 1 ] = ThisNetworkHost
        end
    end
end


-------------------------------------------------------------------------------
--
-- Display a host record as part of a hosts table report
--
function printHostReportRecord ( familiarityTag, NetworkHost )
    local ipNumberString = tostring(NetworkHost.ipNumber)
    local macAddrString  = tostring(NetworkHost.macAddr)
    local description    = NetworkHost.description
    local reportFormat = "%s host: IP number %-13s MAC addr %s %s "

    -- Some hosts will report a description of themselves; if so, include it.
    -- If not, then 'description' will be nil; change to an empty string.
    if description then
        description = "  descr: "..description
    else
        description = ""
    end

    -- Use the provided format string to print this host record.
    print( string.format( reportFormat,
        familiarityTag, ipNumberString, macAddrString, description ) )
end


-------------------------------------------------------------------------------
--
-- Display a report table for one of known/unknown hosts that were found
--
function printHostReport ( SortedHosts, familiarityTag )

    print()

    -- Either report that we didn't find any hosts of this type...
    if #SortedHosts == 0 then
        print( string.format( "No %s hosts found.", familiarityTag ) )
    end

    -- Or print out all the host records for this table.
    for _, ThisHost in ipairs( SortedHosts ) do

        printHostReportRecord( familiarityTag, ThisHost )
    end
end


-------------------------------------------------------------------------------
--
-- Display a pair of tables of the known/unknown hosts that were found
--
function printNetworkHostsReport ( )
    local isKnownTag   = "Known"
    local isUnknownTag = "Unknown"

    -- Start with the known hosts, then the unknown hosts.
    printHostReport( HostsThatAreKnown, isKnownTag )

    printHostReport( HostsThatAreUnknown, isUnknownTag )
end


-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
--
function main ( )

    -- Examine the network to gather data on (visible) hosts.
    -- This data goes into table 'MyLAN'.
    findHostsOnNetwork()

    sortHostsByFamiliarity( MyLAN )

    printNetworkHostsReport()
end


main()

-------------------------------------------------------------------------------
