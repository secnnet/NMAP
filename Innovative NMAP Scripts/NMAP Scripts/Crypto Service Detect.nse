local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"
local string = require "string"
local table = require "table"

description = [[
Detects cryptocurrency and blockchain services by analyzing known blockchain
node endpoints, mining pool interfaces, cryptocurrency exchange APIs, and
wallet services. This script identifies Bitcoin, Ethereum, and other
cryptocurrency-related services.

WARNING: This script should only be used on systems you own or have explicit 
permission to test. Unauthorized scanning may violate terms of service.
]]

---
-- @usage
-- nmap --script crypto-service-detect -p 8332,8333,30303,9944 <target>
-- nmap --script crypto-service-detect --script-args check-rpc=true <target>
--
-- @output
-- PORT     STATE SERVICE
-- 8333/tcp open  bitcoin
-- | crypto-service-detect: 
-- |   Service Type: Bitcoin Node
-- |   Network: Mainnet
-- |   Version: Bitcoin Core 0.21.1
-- |   Block Height: 750000
-- |   Connections: 8
-- |   RPC Interface: Available
-- |   Wallet: Enabled
-- |_  Mining: Disabled
--
-- @args crypto-service-detect.check-rpc Test RPC interfaces (default: false)
-- @args crypto-service-detect.timeout Timeout for requests (default: 5)

author = "Bilel Graine"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "version"}

portrule = shortport.port_or_service({8332, 8333, 8334, 30303, 30304, 9944, 9933, 26656, 26657}, 
    {"bitcoin", "bitcoin-testnet", "ethereum", "polkadot", "cosmos"})

-- Cryptocurrency service signatures
local crypto_services = {
    bitcoin = {
        ports = {8333, 8332, 8334},
        rpc_methods = {"getblockchaininfo", "getnetworkinfo", "getwalletinfo"},
        headers = {"content-type.*application/json"},
        network_magic = {
            mainnet = "f9beb4d9",
            testnet = "0b110907",
            regtest = "fabfb5da"
        },
        service_name = "Bitcoin Node"
    },
    ethereum = {
        ports = {30303, 30304, 8545, 8546},
        rpc_methods = {"eth_blockNumber", "eth_syncing", "net_version"},
        headers = {"content-type.*application/json"},
        service_name = "Ethereum Node"
    },
    litecoin = {
        ports = {9333, 9332},
        rpc_methods = {"getblockchaininfo", "getnetworkinfo"},
        headers = {"content-type.*application/json"},
        service_name = "Litecoin Node"
    },
    monero = {
        ports = {18080, 18081},
        rpc_methods = {"get_info", "get_height"},
        headers = {"content-type.*application/json"},
        service_name = "Monero Node"
    },
    polkadot = {
        ports = {9944, 9933},
        rpc_methods = {"system_chain", "system_version", "system_health"},
        headers = {"content-type.*application/json"},
        service_name = "Polkadot Node"
    },
    cosmos = {
        ports = {26656, 26657},
        rpc_methods = {"status", "health", "genesis"},
        endpoints = {"/status", "/health", "/genesis"},
        service_name = "Cosmos Node"
    }
}

-- Mining pool signatures
local mining_pools = {
    stratum = {
        ports = {3333, 4444, 9999},
        protocol = "stratum",
        test_message = '{"id":1,"method":"mining.subscribe","params":[]}\n'
    },
    getwork = {
        ports = {8332, 8334},
        rpc_methods = {"getwork", "getblocktemplate"}
    }
}

-- Exchange and wallet service patterns
local exchange_patterns = {
    binance = {"binance", "bnb", "bep-"},
    coinbase = {"coinbase", "gdax", "pro.coinbase"},
    kraken = {"kraken", "kraken.com"},
    bitfinex = {"bitfinex", "bfx"},
    huobi = {"huobi", "hbg"}
}

-- Function to test RPC interface
local function test_rpc_interface(host, port, methods, timeout)
    local rpc_info = {}
    
    for _, method in ipairs(methods) do
        local rpc_request = '{"jsonrpc":"2.0","id":1,"method":"' .. method .. '","params":[]}'
        
        local response = http.post(host, port, "/", {
            timeout = timeout,
            header = {
                ["Content-Type"] = "application/json",
                ["Authorization"] = "Basic " .. stdnse.base64("user:pass")
            }
        }, rpc_request)
        
        if response and response.status then
            if response.status == 200 then
                rpc_info[method] = {
                    status = "success",
                    response = response.body
                }
            elseif response.status == 401 then
                rpc_info[method] = {
                    status = "auth_required",
                    response = "Authentication required"
                }
            else
                rpc_info[method] = {
                    status = "error",
                    code = response.status
                }
            end
        end
    end
    
    return rpc_info
end

-- Function to extract Bitcoin information
local function extract_bitcoin_info(rpc_responses)
    local info = {}
    
    if rpc_responses["getblockchaininfo"] and rpc_responses["getblockchaininfo"].response then
        local blockchain_info = rpc_responses["getblockchaininfo"].response
        
        local blocks = blockchain_info:match('"blocks":(%d+)')
        if blocks then
            info["Block Height"] = blocks
        end
        
        local chain = blockchain_info:match('"chain":"([^"]+)"')
        if chain then
            info["Network"] = chain:gsub("^%l", string.upper)
        end
        
        local verification = blockchain_info:match('"verificationprogress":([%d%.]+)')
        if verification then
            local progress = tonumber(verification)
            if progress then
                info["Sync Progress"] = string.format("%.1f%%", progress * 100)
            end
        end
    end
    
    if rpc_responses["getnetworkinfo"] and rpc_responses["getnetworkinfo"].response then
        local network_info = rpc_responses["getnetworkinfo"].response
        
        local version = network_info:match('"version":(%d+)')
        if version then
            info["Version"] = "Bitcoin Core " .. version
        end
        
        local connections = network_info:match('"connections":(%d+)')
        if connections then
            info["Connections"] = connections
        end
        
        local subversion = network_info:match('"subversion":"([^"]+)"')
        if subversion then
            info["Client"] = subversion:gsub("/", ""):gsub(":", " ")
        end
    end
    
    if rpc_responses["getwalletinfo"] then
        if rpc_responses["getwalletinfo"].status == "success" then
            info["Wallet"] = "Enabled"
        elseif rpc_responses["getwalletinfo"].status == "error" then
            info["Wallet"] = "Disabled"
        end
    end
    
    return info
end

-- Function to extract Ethereum information
local function extract_ethereum_info(rpc_responses)
    local info = {}
    
    if rpc_responses["eth_blockNumber"] and rpc_responses["eth_blockNumber"].response then
        local block_response = rpc_responses["eth_blockNumber"].response
        local block_hex = block_response:match('"result":"(0x[%x]+)"')
        
        if block_hex then
            local block_number = tonumber(block_hex, 16)
            if block_number then
                info["Block Height"] = tostring(block_number)
            end
        end
    end
    
    if rpc_responses["net_version"] and rpc_responses["net_version"].response then
        local version_response = rpc_responses["net_version"].response
        local network_id = version_response:match('"result":"(%d+)"')
        
        if network_id then
            local networks = {
                ["1"] = "Mainnet",
                ["3"] = "Ropsten",
                ["4"] = "Rinkeby",
                ["5"] = "Goerli",
                ["42"] = "Kovan"
            }
            
            info["Network"] = networks[network_id] or ("Network ID: " .. network_id)
        end
    end
    
    if rpc_responses["eth_syncing"] and rpc_responses["eth_syncing"].response then
        local sync_response = rpc_responses["eth_syncing"].response
        
        if string.find(sync_response, '"result":false') then
            info["Sync Status"] = "Synced"
        else
            info["Sync Status"] = "Syncing"
        end
    end
    
    return info
end

-- Function to detect mining services
local function detect_mining_services(host, port, timeout)
    local mining_info = {}
    
    -- Test Stratum protocol
    local stratum_test = '{"id":1,"method":"mining.subscribe","params":[]}\n'
    
    -- Create a simple TCP connection test for Stratum
    local socket = nmap.new_socket()
    socket:set_timeout(timeout * 1000)
    
    local status = socket:connect(host, port)
    if status then
        socket:send(stratum_test)
        local response_status, response = socket:receive()
        socket:close()
        
        if response_status and response then
            if string.find(response:lower(), "mining") or string.find(response:lower(), "stratum") then
                mining_info["Protocol"] = "Stratum"
                mining_info["Service Type"] = "Mining Pool"
                
                -- Try to extract pool information
                local pool_name = response:match('"([^"]*pool[^"]*)"')
                if pool_name then
                    mining_info["Pool Name"] = pool_name
                end
            end
        end
    end
    
    return mining_info
end

-- Function to detect exchange services
local function detect_exchange_services(host, port, timeout)
    local exchange_info = {}
    
    -- Test common exchange API endpoints
    local api_endpoints = {
        "/api/v1/ping",
        "/api/v3/ping",
        "/v1/ping",
        "/api/ping",
        "/health",
        "/status"
    }
    
    for _, endpoint in ipairs(api_endpoints) do
        local response = http.get(host, port, endpoint, {timeout = timeout})
        
        if response and response.status == 200 and response.body then
            local body_lower = response.body:lower()
            
            for exchange, patterns in pairs(exchange_patterns) do
                for _, pattern in ipairs(patterns) do
                    if string.find(body_lower, pattern:lower()) then
                        exchange_info["Service Type"] = "Cryptocurrency Exchange"
                        exchange_info["Exchange"] = exchange:gsub("^%l", string.upper)
                        return exchange_info
                    end
                end
            end
            
            -- Check for generic exchange indicators
            if string.find(body_lower, "trade") or string.find(body_lower, "order") or 
               string.find(body_lower, "balance") or string.find(body_lower, "ticker") then
                exchange_info["Service Type"] = "Cryptocurrency Exchange API"
            end
        end
    end
    
    return exchange_info
end

action = function(host, port)
    local timeout = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".timeout")) or 5
    local check_rpc = stdnse.get_script_args(SCRIPT_NAME .. ".check-rpc")
    
    local results = {}
    local service_detected = false
    
    -- Check for cryptocurrency node services
    for crypto_type, service_info in pairs(crypto_services) do
        for _, service_port in ipairs(service_info.ports) do
            if port.number == service_port then
                service_detected = true
                results["Service Type"] = service_info.service_name
                
                -- Test RPC interface if requested
                if check_rpc and service_info.rpc_methods then
                    local rpc_responses = test_rpc_interface(host, port, service_info.rpc_methods, timeout)
                    
                    if next(rpc_responses) then
                        results["RPC Interface"] = "Available"
                        
                        -- Extract service-specific information
                        if crypto_type == "bitcoin" then
                            local bitcoin_info = extract_bitcoin_info(rpc_responses)
                            for key, value in pairs(bitcoin_info) do
                                results[key] = value
                            end
                        elseif crypto_type == "ethereum" then
                            local ethereum_info = extract_ethereum_info(rpc_responses)
                            for key, value in pairs(ethereum_info) do
                                results[key] = value
                            end
                        end
                    else
                        results["RPC Interface"] = "Protected/Unavailable"
                    end
                end
                
                break
            end
        end
    end
    
    -- Check for mining services
    local mining_info = detect_mining_services(host, port, timeout)
    if next(mining_info) then
        service_detected = true
        for key, value in pairs(mining_info) do
            results[key] = value
        end
    end
    
    -- Check for exchange services
    local exchange_info = detect_exchange_services(host, port, timeout)
    if next(exchange_info) then
        service_detected = true
        for key, value in pairs(exchange_info) do
            results[key] = value
        end
    end
    
    -- Return results only if a cryptocurrency service was detected
    if service_detected then
        return results
    else
        return nil
    end
end

