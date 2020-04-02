#! /usr/bin/env lua

-------------------------------------------------------------------------------
--
-- Read in the local network's database of known hosts

-- The local network's database of known hosts as a list (Lua sequence).
local NetworkDatabase = require "mac-addresses"
-- Contains two tables of network objects:
    -- Subnets = subnet object table with the following string fields:
        -- Subnet type, which is one of:
            -- ipv4subnet = xxx.xxx.xxx.xxx/yy
            -- ipv6subnet = xxxx:xxxx etc
        -- description
    -- KnownHosts = host object table with the following string fields:
        -- macAddr = xx:xx:xx:xx:xx:xx
        -- description
        -- vendor [optional]

-- 'NetworkDatabase' as an associative array keyed by its MAC addresses.
local DatabaseOfHostsByMAC = { }

-- The local network's hosts, as a list (Lua sequence) of host abjects.
local AllDiscoveredHosts = { }
-- Each host object is a table with the following fields (all strings):
    -- ipNumber
    -- status
    -- macAddr
    -- description [optional]
    -- vendor [optional]

-- Can't scan the entire internet...  Draw the line somewhere.
local minCIDR = 8

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
--
-- Do a simple validation of the format & value of an IPv6 subnet string
--
function validateIPv6subnet ( subnet, description )

    -- The subnet passed in may not be our type; if not, ignore it.
    if not subnet then return end

    -- We will implement this subnet type later...
    print( "IPv6 subnet support is not (yet) implemented!" )
    print( "Cannot scan subnet '"..description.."'; skipping..." )
    -- print()
end


-------------------------------------------------------------------------------
--
-- Do a simple validation of the format & value of an IPv4 subnet string
--
function validateIPv4subnet ( subnet, description )
    local Octets = { }
    local cidr

    -- The subnet passed in may not be our type; if not, ignore it.
    if type(subnet) ~= "string" then return end

    -- We can allow the 'description' field to be optional.
    description = description or "<no-name>"

    -- Extract a subnet in the form of 'xxx.xxx.xxx.xxx/yy'.
    -- Since there are 4 octets, build an array and process with a for loop.
    Octets = {
        subnet:match( "(%d+)%.(%d+)%.(%d+)%.(%d+)%/(%d+)" ),
        }

    -- Notice that there are _5_ values, however; Swap the 5th with the
    -- 'cidr' variable, which conveniently will be 'nil'.  This not only
    -- sets 'cidr' from the array value, it nicely erases it from the array.
    cidr,Octets[5] = Octets[5],cidr

    -- A CIDR value is required.
    if not cidr then
        error( "Bad subnet: CIDR value missing for subnet '"..description.."'" )
    end

    -- Get CIDR spec as a number; Max=32; Min=0 means "the entire internet".
    cidr = tonumber( cidr )

    -- Don't allow the entire internet (!); cut off at Class A searches.
    if cidr < minCIDR or cidr > 32 then
        error( "Bad subnet: CIDR value ("..cidr..
            ") out of range ("..minCIDR..
            "..32) for subnet '"..description.."'" )
    end

    -- Scan each octet and ensure values from 0..255.
    for index, octet in ipairs( Octets ) do

        -- Get the octet as a number.
        octet = tonumber( octet )

        if octet < 0 or octet > 255 then
            error( "Subnet octet #"..index.." for '"..
                description.."' is out of range (0..255)" )
        end
    end
end


-------------------------------------------------------------------------------
--
-- Validate the Network Database Subnets table
--
function validateSubnets ( Subnets )
    local dataType = type( Subnets )

    -- First off, the Subnets table has to actually exist as a table.
    if dataType ~= "table" then
        error "Missing or corrupt 'Subnets' table in Network Database file!"
    end

    -- Then, examine/validate each subnet object in the table.
    for index, Subnet in ipairs( Subnets ) do

        -- We need Subnet fields, so each Subnet must itself be a table.
        if dataType ~= "table" then
            error( "Found a '"..dataType.."' for 'Subnets' element "..
                index.." in the Network Database file!" )
        end

        -- One of the following should succeed, else unknown network type.
        validateIPv4subnet( Subnet.ipv4subnet, Subnet.description )
        validateIPv6subnet( Subnet.ipv6subnet, Subnet.description )
    end
end


-------------------------------------------------------------------------------
--
-- Validate the Network Database KnownHosts table
--
function validateMACaddress ( macAddress )
    local dataType = type( KnownHosts )

    -- This loop depends on the host object having a MAC address.
    if type(macAddress) ~= "string" then
        error( "Host #"..index..
            " in the Network Database file has no MAC address!" )
    end

    -- Extract a MAC address in the form of 'xx:xx:xx:xx:xx:xx'.
    -- Since there are 6 octets, build an array and process with a for loop.
    Octets = {
        macAddress:match( "(%x%x)%:(%x%x)%:(%x%x)%:(%x%x)%:(%x%x)%:(%x%x)" ),
        }

    -- Scan each octet and ensure values from 0..255.
    for index, octet in ipairs( Octets ) do

        -- Get the octet as a hex number.
        octet = tonumber( octet, 16 )

        if octet < 0 or octet > 255 then
            error( "Subnet octet #"..index.." for '"..
                description.."' is out of range (0..255)" )
        end
    end

    -- Ensure that the MAC address is normalized to uppercase.
    return macAddress:upper()
end


-------------------------------------------------------------------------------
--
-- Validate the Network Database KnownHosts table
--
function validateKnownHosts ( KnownHosts )
    local dataType = type( KnownHosts )

    -- First off, the KnownHosts table has to actually exist as a table.
    if dataType ~= "table" then
        error "Missing or corrupt 'KnownHosts' table in Network Database file!"
    end

    -- Then, examine/validate each host object in the table.
    for index, KnownHost in ipairs( KnownHosts ) do

        -- We need KnownHost fields, so each KnownHost must itself be a table.
        if dataType ~= "table" then
            error( "Found a '"..dataType.."' for 'KnownHosts' element "..
                index.." in the Network Database file!" )
        end

        -- The MAC address field is mandatory & needs format verification.
        local macAddress = KnownHost.macAddr

        if type(macAddress) ~= "string" then
            error( "Host #"..index..
                " in the Network Database file has no MAC address!" )
        end

        -- Ensure that the MAC address is normalized to uppercase.
        KnownHost.macAddr = validateMACaddress( macAddress )

        -- The description field is mandatory.
        if type( KnownHost.description ) ~= "string" then
            error( "Host #"..index..
                " in the Network Database file has no description!" )
        end
    end
end


-------------------------------------------------------------------------------
--
-- Validate the NetworkDatabase table prior to using its data
--
function validateNetworkDatabase ( Database )

    validateSubnets( Database.Subnets )

    validateKnownHosts( Database.KnownHosts )
end


-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
--
-- Sort a hosts database into an associative array keyed by MAC address
--
function sortHostsByMACaddress ( DatabaseOfHosts )
    HostsByMAC = { }

    -- Turn the DatabaseOfHosts sequence "inside out" to make an
    -- associative array of each known host keyed by its MAC addr.
    for index, DatabaseHost in ipairs( DatabaseOfHosts ) do

        HostsByMAC[ DatabaseHost.macAddr ] = DatabaseHost
    end

    return HostsByMAC
end


-------------------------------------------------------------------------------
--
-- Function to have the OS run a shell command
--
function runShellCommand( shellCommand, resultHandler )
    -- Run a (bash) shell command in the host operating system.  Note
    -- that we can't receive the shell command output directly, but we
    -- CAN tell the host OS to redirect the output to a (temp) file.
    -- Note that we can't use 'mktemp': We can't receive its output,
    -- which is its name/path!  So we'll have to provide a path.
    local tempFile = "/tmp/lua-shell-cmd"

    -- Attempt to execute the given shell command, instructing the host
    -- OS to redirect its output to a results file...
    if not os.execute( shellCommand.." > "..tempFile ) then
        error( "Execution of OS command '"..shellCommand.."' failed!" )
    end

    -- ...Then open the file.
    if not io.input( tempFile ) then
        error( "Cannot open file '"..tempFile..
            "' containing OS command results!" )
    end

    -- The shell command executed without an error, producing a result
    -- file of the command's output AND we were able to open the file.
    -- Loop through each line of output, calling a handler to parse it.
    for line in io.lines() do
        -- Screen out blank (empty) lines, and only pass non-blank
        -- lines to the result handler function for processing.
        if line:match( "%w" ) then
            -- Call the result handler function with the line.
            resultHandler = resultHandler( line )

            -- This function will return a new result handler if
            -- additional output is expected, or nil if no additional
            -- parsing is needed/expected.  If nil, break out of this
            -- loop and throw away any remaining results lines.
            if not resultHandler then break end
        end
    end

    -- Close the output result file and remove it from the host file system.
    io.input():close()
    os.remove( tempFile )
end


-------------------------------------------------------------------------------
--
-- Function to query the OS to get hosts on the local network
--
function ScanNetworkForHosts ( Subnet )
    local AllDiscoveredHosts = { }

    -- Determine whether IPv4 or IPv6
    local thisSubnet = Subnet.ipv4subnet

    -- IPv6 subnet scanning requires an additional CLI switch.
    if not thisSubnet then
        thisSubnet = "-6 "..Subnet.ipv6subnet
    end

    -- Use the subnet (string) to form a shell command to carry out
    -- the scan.  We'll use 'nmap' with a simple ping test.
    -- This can be made more complex/thorough, if desired.
    local shellCommand = "sudo nmap -n -sP "..thisSubnet

    -- Define results handler functions for parsing the lines of the
    -- results file.  The 'nmap' report consists of a a header line,
    -- followed by one or more 3-line host records, then an ending line.
    -- Consequently, we'll need to change handlers in sync with the
    -- type of output line we parse.  (Only 3 handlers are needed, not 5.)
    --
    -- The extracted host data goes into a table defined here, which is
    -- a 'non-local variable' to each of the handlers defined below.
    -- Note also that each of the results handler functions is ALSO
    -- a non-local variable to the other functions, which dynamically
    -- change which function the shell command (above) calls.  Since
    -- we have recursive indirect functions, we must pre-declare them.

    local resultHandlerInitial
    local resultHandlerMiddle
    local resultHandlerFinal


    resultHandlerInitial = function ( line )
        -- Attempt to match the 1st of 3 lines returned for each host.
        local ipNumber = line:match( "Nmap scan report for (%S+)" )

        -- If this is a new host record, the above return is non-nil.
        -- In that case, create a new host 'object' and set its IP number.
        -- Add the new host table to the array of discovered hosts.
        if ipNumber then
            AllDiscoveredHosts[ #AllDiscoveredHosts + 1 ] =
                { ipNumber=ipNumber }

            -- Update the handler to parse the 2nd line of the record.
            return resultHandlerMiddle
        end

        -- It was NOT the first line of a host record -- which is OK.
        -- But now it's required to be the first line of the entire
        -- report.  Either match text from that line or throw an error.
        if not line:match( "Starting Nmap" ) then
            error( "Could not detect start of 'nmap' scan!" )
        end

        -- If we do match the first line of the report, continue using
        -- this same handler, since the very next line of the output
        -- should be a "Line 1" of the first host record.
        return resultHandlerInitial
    end


    resultHandlerMiddle = function ( line )
        -- Attempt to match the 2nd of 3 lines returned for each host.
        local status = line:match( "Host is (%w+)" )

        -- The above should have matched; if not, the scan failed.
        if not status then
            error( "Network scan failed for host with IP '"..
                AllDiscoveredHosts[ #AllDiscoveredHosts ].ipNumber.."'! " )
        end

        -- Capture the status in the current host record.
        AllDiscoveredHosts[ #AllDiscoveredHosts ].status = status

        -- Update the handler to parse the 3rd line of the record.
        return resultHandlerFinal
    end


    resultHandlerFinal = function ( line )
        -- Attempt to match the 3rd of 3 lines returned for each host.
        local macAddr, vendor = line:match( "MAC Address: (%S+)%s+(.+)" )

        -- The above should have matched, so capture the MAC address and
        -- vendor information (if provided).  Again, don't increment the
        -- sequence index; this will be done on line 1 of the next record.
        if macAddr then
            AllDiscoveredHosts[ #AllDiscoveredHosts ].macAddr = macAddr:upper()
            AllDiscoveredHosts[ #AllDiscoveredHosts ].vendor  = vendor

            -- Update the handler to parse the 1st line of the NEXT record.
            return resultHandlerInitial
        end

        -- It was NOT the last line of a host record -- which is OK.
        -- But now it's required to be the last line of the entire
        -- report.  Either match text from that line or throw an error.
        if not line:match( "Nmap done" ) then
            error( "Could not detect end of 'nmap' scan!" )
        end

        -- If it DID match the last line of the report, then we must
        -- return nil (the default) to signal the output parser to stop.
    end

    runShellCommand( shellCommand, resultHandlerInitial )
    return AllDiscoveredHosts
end


-------------------------------------------------------------------------------
--
-- Function to query the OS to get this platform's NIC data
--
function getAllMyNICs ( )
    local MyNICs = { }
    local shellCommand = "ip -br addr"

    -- The handler is a self-referential recursively-called function.
    -- Its 'name' isn't defined until, well, it's defined.  So it can't
    -- refer to itself without a pre-existing definition, so define it now.
    local resultHandler

    resultHandler = function ( line )
        -- Parse a line from the above shell command.
        -- If the line fails to parse, the returns are nil.
        local deviceName, ipNumber = line:match( "(%w+)%s+UP%s+([^/]+)" )

        -- If the IP device is "up", then add it as a table to the NICs array.
        -- Note that 'MyNICs' is captured as a non-local variable.
        if deviceName then MyNICs[ #MyNICs + 1 ] =
            { deviceName=deviceName, ipNumber=ipNumber }
        end

        -- We only return nil (default) if we've completed scanning the
        -- output of the shell command.  But we want to process all lines
        -- in the shell command result, so return this function.
        return resultHandler
    end

    runShellCommand( shellCommand, resultHandler )
    return MyNICs
end


-------------------------------------------------------------------------------
--
-- Function to query the OS to get this platform's NICs' MAC addresses
--
function getAllMyMACs ( )
    local MyMACs = { }
    local shellCommand = "ip -o -f link addr"

    -- The handler is a self-referential recursively-called function.
    -- Its 'name' isn't defined until, well, it's defined.  So it can't
    -- refer to itself without a pre-existing definition, so define it now.
    local resultHandler

    resultHandler = function ( line )
        -- Parse a line from the above shell command.
        -- If the line fails to parse, the returns are nil.
        local deviceName, macAddr = line:match( "%d+: (%w+):.+ether (%S+)" )

        -- If the IP device is an ethernet device, then add it as a table
        -- to the MACs array.  Note that 'MyMACs' is a non-local variable.
        if deviceName then MyMACs[ #MyMACs + 1 ] =
            { deviceName=deviceName, macAddr=macAddr:upper() }
        end

        -- We only return nil (default) if we've completed scanning the
        -- output of the shell command.  But we want to process all lines
        -- in the shell command result, so return this function.
        return resultHandler
    end

    runShellCommand( shellCommand, resultHandler )
    return MyMACs
end


-------------------------------------------------------------------------------
--
-- Function to query the OS to get this platform's vendor
--
function getMyVendor ( myMACaddress )
    local myVendorName
    local shellCommand = "sudo lshw"

    -- If this information is in the database, don't derive it.
    if myMACaddress then
        myVendorName = DatabaseOfHostsByMAC[ myMACaddress ].vendor

        if myVendorName then return myVendorName end
    end

    -- The handler is a self-referential recursively-called function.
    -- Its 'name' isn't defined until, well, it's defined.  So it can't
    -- refer to itself without a pre-existing definition, so define it now.
    local resultHandler

    resultHandler = function ( line )
        -- Parse a line from the above shell command.
        -- If the line fails to parse, the return is nil.
        -- Note that 'myVendorName' is a non-local variable.
        myVendorName = line:match( "vendor: ([^]]+)" )

        -- We return nil (default) if we've completed scanning the output
        -- of the shell command.  If the above match succeeds, we're done!
        if myVendorName then return end

        -- Otherwise, return this function to be called again.
        return resultHandler
    end

    runShellCommand( shellCommand, resultHandler )
    return myVendorName
end


-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
--
-- Function to determine the device name of the NIC using my IP number
--
function myNICnameFromIPnumber ( myIPnumber )
    -- Ensure that we were passed a valid IP number.
    if not myIPnumber then
        error "Cannot resolve an interface name from a 'nil' IP number!"
    end

    -- Scan the sequence of my NICs to find the one bound to my IP number.
    for _, ThisNIC in ipairs( getAllMyNICs() ) do
        -- Ensure that the NIC has an ipNumber field.
        if not ThisNIC or not ThisNIC.ipNumber then
            error( "Network interface '"..ThisNIC.deviceName..
                "' has no IP number!" )
        end

        if ThisNIC.ipNumber == myIPnumber then
            if ThisNIC.deviceName then return ThisNIC.deviceName end

            error( "Network interface with IP number '"..
                ThisNIC.ipNumber.."' has no description!" )
        end
    end

    -- We should have found a match.  (We did successfully scan the network.)
    error( "Cannot find my own network interface device!" )
end


-------------------------------------------------------------------------------
--
-- Function to determine the MAC address of the NIC with my device name
--
function myMACaddrFromNICname ( myNICname )
    -- Ensure that we were passed a valid name.
    if not myNICname then
        error "Cannot resolve a MAC address from a 'nil' interface name!"
    end

    -- Scan the sequence of my MACs to find the one bound to my device name.
    for _, ThisMAC in ipairs( getAllMyMACs() ) do

        -- Ensure that the MAC address has a deviceName field.
        if not ThisMAC or not ThisMAC.deviceName then
            error( "Network interface '"..ThisMAC.macAddr..
                "' has no device name!" )
        end

        if ThisMAC.deviceName == myNICname then
            if ThisMAC.macAddr then return ThisMAC.macAddr end

            error( "Network interface '"..
                ThisMAC.deviceName.."' has no MAC address!" )
        end
    end

    -- We should have found a match.  (We did successfully scan the network.)
    error( "Cannot find my own network device's MAC address!" )
end


-------------------------------------------------------------------------------
--
-- Function to determine the MAC address of my NIC on my LAN
--
function getMyMacAddr ( myIPnumber )

    -- Determine the device name of my NIC used on the network.
    local myNICname = myNICnameFromIPnumber( myIPnumber )

    -- Use that name to determine the MAC address for the IP number.
    return myMACaddrFromNICname( myNICname )
end


-------------------------------------------------------------------------------
--
-- Function to get a table of all the devices detected on the network
--
function findHostsOnNetwork ( Subnet )
    local MyHost
    local subnetDescr = Subnet.description

    -- Scan the network to discover hosts.
    DiscoveredHosts = ScanNetworkForHosts( Subnet )

    -- Did we get anything?  (Should get at least the host...)
    if #DiscoveredHosts < 1 then
        error( "Scan of network "..subnetDescr..
            " did not return ANY hosts! " )
    end

    -- Extract my host, since it isn't reported in the same way.
    -- Note that my host is always the last one in the list (sequence).
    MyHost = DiscoveredHosts[ #DiscoveredHosts ]

    -- Resolve the missing information for my host by different means.
    MyHost.macAddr = getMyMacAddr( MyHost.ipNumber )
    MyHost.vendor = "("..getMyVendor( MyHost.macAddr )..")"

    -- Now restore my host to the discovered hosts table.
    DiscoveredHosts[ #DiscoveredHosts ] = MyHost

    return DiscoveredHosts
end


-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
--
-- Gather the data, crunch it, and display the results
--
function sortHostsByFamiliarity ( HostsFoundOnNetwork )
    local HostsThatAreKnown   = { }
    local HostsThatAreUnknown = { }

    -- Sort the discovered hosts into two tables, depending on whether or
    -- not they are known hosts (listed in the 'NetworkDatabase' table).
    for _, ThisNetworkHost in ipairs( HostsFoundOnNetwork ) do
        -- Ensure that the host has a MAC address (will be used as a key).
        if not ThisNetworkHost.macAddr then
            error( "MAC address missing for discovered host at IP number '"..
                ThisNetworkHost.ipNumber.."' " )
        end

        -- If this host is in the database, the lookup is non-nil.
        local DatabaseHost = DatabaseOfHostsByMAC[ ThisNetworkHost.macAddr ]

        if DatabaseHost then
            -- If known, set this host's description field from the database.
            ThisNetworkHost.description = DatabaseHost.description

            -- Create a new host object in the list of known hosts.
            HostsThatAreKnown[ #HostsThatAreKnown + 1 ] = ThisNetworkHost
        else
            -- Create a new unknown host, so it won't have a description.
            HostsThatAreUnknown[ #HostsThatAreUnknown + 1 ] = ThisNetworkHost
        end
    end

    return HostsThatAreKnown, HostsThatAreUnknown
end


-------------------------------------------------------------------------------
--
-- Display a host record as part of a hosts table report
--
function printHostReportRecord ( familiarityTag, NetworkHost )
    local ipNumberString = NetworkHost.ipNumber
    local macAddrString  = NetworkHost.macAddr
    local description    = NetworkHost.description
    local reportFormat = "%s host: IP number %-14s MAC addr %s %s "

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
function printHostReport ( Subnet, SortedHosts, familiarityTag )

    print()

    -- Either report that we didn't find any hosts of this type...
    if #SortedHosts == 0 then
        print( string.format( "No %s hosts found.", familiarityTag ) )
        return
    end

    -- Or print out the host records for this subnet.
    print( "Subnet '"..Subnet.description.."': " )

    -- Print out all the host records for this table type.
    for _, ThisHost in ipairs( SortedHosts ) do

        printHostReportRecord( familiarityTag, ThisHost )
    end
end


-------------------------------------------------------------------------------
--
-- Display a pair of tables of the known/unknown hosts that were found
--
function genNetworkHostsReport ( Subnet,
        HostsThatAreKnown, HostsThatAreUnknown )
    local isKnownTag   = "Known"
    local isUnknownTag = "Unknown"

    -- Start with the known hosts, then the unknown hosts.
    printHostReport( Subnet, HostsThatAreKnown, isKnownTag )

    printHostReport( Subnet, HostsThatAreUnknown, isUnknownTag )
end


-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
--
function main ( Database )
    local HostsThatAreKnown
    local HostsThatAreUnknown

    -- Validate the network database read in from another file.
    validateNetworkDatabase( Database )

    -- Sort the known hosts database into an assoc array keyed by MAC address.
    DatabaseOfHostsByMAC = sortHostsByMACaddress( Database.KnownHosts )

    -- Now process each subnet in the list of subnets.
    for _, Subnet in ipairs( Database.Subnets ) do

        -- Examine the network to gather data on (visible) hosts.
        AllDiscoveredHosts = findHostsOnNetwork( Subnet )

        -- Sort what we found into lists of known & unknown hosts.
        HostsThatAreKnown, HostsThatAreUnknown =
            sortHostsByFamiliarity( AllDiscoveredHosts )

        -- Generate a report of what we found.
        genNetworkHostsReport( Subnet, HostsThatAreKnown, HostsThatAreUnknown )
    end
end


main( NetworkDatabase )

-------------------------------------------------------------------------------
