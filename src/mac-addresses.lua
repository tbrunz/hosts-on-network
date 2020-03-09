--
-- Lua database for known hosts network parameters
--

NetworkDatabase = { }

-- The network configuration
NetworkDatabase.NetworkIPv4 = {

    subnet = "192.168.1.0",
    CIDR   = 24,
}


NetworkDatabase.HostsByMAC = {

    { macAddr = "AA:BB:01:02:03:CC:DD",
        description = "My laptop's Wifi",
    },

    { macAddr = "44:55:EE:FF:66:77",
        description = "My home Wifi router",
    },
}

return NetworkDatabase
