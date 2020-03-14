#! /usr/bin/env lua

-------------------------------------------------------------------------------
--
-- Read in the local network's database of known hosts
--
NetworkDatabase = require "mac-addresses"


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
function ScanNetworkForHosts ( subnet )
    local AllDiscoveredHosts = { }

    -- Use the subnet (string) to form a shell command to carry out
    -- the scan.  We'll use 'nmap' with a simple ping test.
    -- This can be made more complex/thorough, if desired.
    local shellCommand = "sudo nmap -n -sP "..subnet

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

        -- The above should have matched, so capture the status in the
        -- current host record (i.e., don't increment the index yet).
        if status then
            AllDiscoveredHosts[ #AllDiscoveredHosts ].status = status

            -- Update the handler to parse the 3rd line of the record.
            return resultHandlerFinal
        end
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
function getMyVendor ( )
    local myVendorName
    local shellCommand = "sudo lshw"

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

    -- Scan the sequence of my NICs to find the one bound to my IP number.
    for _, ThisNIC in ipairs( getAllMyNICs() ) do

        if ThisNIC.ipNumber == myIPnumber then
            return ThisNIC.deviceName
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

    -- Scan the sequence of my MACs to find the one bound to my device name.
    for _, ThisMAC in ipairs( getAllMyMACs() ) do

        if ThisMAC.deviceName == myNICname then
            return ThisMAC.macAddr
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
function findHostsOnNetwork ( subnet )
    local MyHost

    -- Scan the network to discover hosts.
    DiscoveredHosts = ScanNetworkForHosts( subnet )

    -- Did we get anything?  (Should get at least the host...)
    if #DiscoveredHosts < 1 then
        error( "Scan of network "..subnet.." did not return ANY hosts! " )
    end

    -- Extract my host, since it isn't reported in the same way.
    -- Note that my host is always the last one in the list (sequence).
    MyHost = DiscoveredHosts[ #DiscoveredHosts ]

    -- Resolve the missing information for my host by different means.
    MyHost.macAddr = getMyMacAddr( MyHost.ipNumber )
    MyHost.vendor = "("..getMyVendor()..")"

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
    local DatabaseHostByMAC = { }

    -- Turn the NetworkDatabase sequence "inside out" to make an
    -- associative array of each known host keyed by its MAC addr.
    for _, DatabaseHost in ipairs( NetworkDatabase.HostsByMAC ) do
        --
        -- Extract the host's MAC address to use as the key to itself.
        DatabaseHostByMAC[ DatabaseHost.macAddr:upper() ] = DatabaseHost
    end

    -- Empty the two 'sort' tables, then fill them with sorted hosts.
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
    local AllDiscoveredHosts

    -- The subnet we're supposed to scan is in the database file.
    local subnet = NetworkDatabase.NetworkIPv4.subnet.."/"..
        tostring(NetworkDatabase.NetworkIPv4.CIDR)

    -- Examine the network to gather data on (visible) hosts.
    AllDiscoveredHosts = findHostsOnNetwork( subnet )

    sortHostsByFamiliarity( AllDiscoveredHosts )

    printNetworkHostsReport()
end


main()

-------------------------------------------------------------------------------
