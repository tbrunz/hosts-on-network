--
-- Lua database for known hosts network parameters
--

NetworkDatabase = { }

-- The network configuration
NetworkDatabase.Subnets = {

    {   ipv4subnet = "192.168.1.0/24",
        description = "My home LAN",
    },
}


NetworkDatabase.KnownHosts = {

    {   macAddr = "AA:BB:01:02:CC:DD",
        description = "My laptop's Wifi",
        vendor = "Big Computer Maker, Inc.",
    },

    {   macAddr = "44:55:EE:FF:66:77",
        description = "My home Wifi router",
    },
}

return NetworkDatabase
