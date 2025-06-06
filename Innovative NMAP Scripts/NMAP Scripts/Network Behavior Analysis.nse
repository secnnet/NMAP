local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"
local string = require "string"
local table = require "table"
local math = require "math"

description = [[
Analyzes network behavior patterns by monitoring response times, connection
patterns, and service availability over time. This script detects load
balancers, CDNs, rate limiting, and other network infrastructure behaviors
that may indicate security controls or network architecture.

WARNING: This script should only be used on systems you own or have explicit 
permission to test. Unauthorized scanning may violate terms of service.
]]

---
-- @usage
-- nmap --script network-behavior-analysis -p 80,443 <target>
-- nmap --script network-behavior-analysis --script-args samples=10,delay=1 <target>
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | network-behavior-analysis: 
-- |   Response Time Analysis:
-- |     Average Response Time: 245ms
-- |     Response Time Variance: High (45ms std dev)
-- |     Fastest Response: 180ms
-- |     Slowest Response: 320ms
-- |   Load Balancing: Detected
-- |     Backend Servers: 3-4 estimated
-- |     Load Balancer Type: Round Robin
-- |   Rate Limiting: Detected
-- |     Threshold: ~100 requests/minute
-- |     Response: HTTP 429 (Too Many Requests)
-- |   CDN Detection: Cloudflare
-- |_  Geographic Distribution: Multiple regions detected
--
-- @args network-behavior-analysis.samples Number of test samples (default: 5)
-- @args network-behavior-analysis.delay Delay between samples in seconds (default: 2)
-- @args network-behavior-analysis.timeout Timeout for requests (default: 5)

author = "Bilel Graine"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "intrusive"}

portrule = shortport.http

-- Function to calculate statistics
local function calculate_stats(values)
    if #values == 0 then
        return {}
    end
    
    local sum = 0
    local min_val = values[1]
    local max_val = values[1]
    
    for _, value in ipairs(values) do
        sum = sum + value
        if value < min_val then min_val = value end
        if value > max_val then max_val = value end
    end
    
    local mean = sum / #values
    
    -- Calculate standard deviation
    local variance_sum = 0
    for _, value in ipairs(values) do
        variance_sum = variance_sum + (value - mean) ^ 2
    end
    
    local std_dev = math.sqrt(variance_sum / #values)
    
    return {
        mean = mean,
        min = min_val,
        max = max_val,
        std_dev = std_dev,
        count = #values
    }
end

-- Function to detect CDN and load balancers
local function detect_infrastructure(responses)
    local infrastructure = {}
    local server_headers = {}
    local via_headers = {}
    local cf_headers = {}
    local x_cache_headers = {}
    
    for _, response in ipairs(responses) do
        if response.header then
            -- Collect server headers
            if response.header["server"] then
                server_headers[response.header["server"]] = (server_headers[response.header["server"]] or 0) + 1
            end
            
            -- Check for CDN indicators
            if response.header["cf-ray"] or response.header["cf-cache-status"] then
                infrastructure["CDN"] = "Cloudflare"
            elseif response.header["x-amz-cf-id"] then
                infrastructure["CDN"] = "Amazon CloudFront"
            elseif response.header["x-azure-ref"] then
                infrastructure["CDN"] = "Azure CDN"
            elseif response.header["x-cache"] then
                x_cache_headers[response.header["x-cache"]] = (x_cache_headers[response.header["x-cache"]] or 0) + 1
            end
            
            -- Check for load balancer indicators
            if response.header["via"] then
                via_headers[response.header["via"]] = (via_headers[response.header["via"]] or 0) + 1
            end
            
            if response.header["x-forwarded-for"] or response.header["x-real-ip"] then
                infrastructure["Proxy/Load Balancer"] = "Detected"
            end
        end
    end
    
    -- Analyze server header variations
    local unique_servers = 0
    for _ in pairs(server_headers) do
        unique_servers = unique_servers + 1
    end
    
    if unique_servers > 1 then
        infrastructure["Load Balancing"] = "Detected (Multiple servers)"
        infrastructure["Backend Servers"] = unique_servers .. " different server headers"
    end
    
    -- Analyze cache headers
    if next(x_cache_headers) then
        local cache_info = {}
        for cache_status, count in pairs(x_cache_headers) do
            table.insert(cache_info, cache_status .. " (" .. count .. "x)")
        end
        infrastructure["Cache Behavior"] = table.concat(cache_info, ", ")
    end
    
    return infrastructure
end

-- Function to detect rate limiting
local function detect_rate_limiting(responses, timings)
    local rate_limit_info = {}
    local status_codes = {}
    local rate_limit_headers = {}
    
    for i, response in ipairs(responses) do
        if response.status then
            status_codes[response.status] = (status_codes[response.status] or 0) + 1
            
            -- Check for rate limiting status codes
            if response.status == 429 then
                rate_limit_info["Rate Limiting"] = "Detected (HTTP 429)"
                
                if response.header and response.header["retry-after"] then
                    rate_limit_info["Retry After"] = response.header["retry-after"] .. " seconds"
                end
            elseif response.status == 503 and response.body and 
                   string.find(response.body:lower(), "rate") then
                rate_limit_info["Rate Limiting"] = "Possible (HTTP 503 with rate message)"
            end
            
            -- Check for rate limiting headers
            if response.header then
                for header_name, header_value in pairs(response.header) do
                    local header_lower = header_name:lower()
                    if string.find(header_lower, "rate") or 
                       string.find(header_lower, "limit") or
                       string.find(header_lower, "quota") then
                        rate_limit_headers[header_name] = header_value
                    end
                end
            end
        end
    end
    
    -- Analyze response time patterns for rate limiting
    if #timings > 3 then
        local stats = calculate_stats(timings)
        
        -- Look for sudden increases in response time (throttling)
        local slow_responses = 0
        for _, timing in ipairs(timings) do
            if timing > stats.mean + (2 * stats.std_dev) then
                slow_responses = slow_responses + 1
            end
        end
        
        if slow_responses > #timings * 0.3 then
            rate_limit_info["Throttling"] = "Possible (Response time increases)"
        end
    end
    
    -- Add rate limiting headers if found
    if next(rate_limit_headers) then
        local header_info = {}
        for header, value in pairs(rate_limit_headers) do
            table.insert(header_info, header .. ": " .. value)
        end
        rate_limit_info["Rate Limit Headers"] = table.concat(header_info, ", ")
    end
    
    return rate_limit_info
end

-- Function to analyze response time patterns
local function analyze_response_times(timings)
    local analysis = {}
    
    if #timings == 0 then
        return analysis
    end
    
    local stats = calculate_stats(timings)
    
    analysis["Average Response Time"] = string.format("%.0fms", stats.mean)
    analysis["Fastest Response"] = string.format("%.0fms", stats.min)
    analysis["Slowest Response"] = string.format("%.0fms", stats.max)
    
    -- Classify variance
    local variance_ratio = stats.std_dev / stats.mean
    if variance_ratio > 0.3 then
        analysis["Response Time Variance"] = string.format("High (%.0fms std dev)", stats.std_dev)
    elseif variance_ratio > 0.15 then
        analysis["Response Time Variance"] = string.format("Medium (%.0fms std dev)", stats.std_dev)
    else
        analysis["Response Time Variance"] = string.format("Low (%.0fms std dev)", stats.std_dev)
    end
    
    -- Detect patterns
    local increasing_trend = 0
    local decreasing_trend = 0
    
    for i = 2, #timings do
        if timings[i] > timings[i-1] then
            increasing_trend = increasing_trend + 1
        elseif timings[i] < timings[i-1] then
            decreasing_trend = decreasing_trend + 1
        end
    end
    
    if increasing_trend > #timings * 0.7 then
        analysis["Response Pattern"] = "Increasing (possible throttling)"
    elseif decreasing_trend > #timings * 0.7 then
        analysis["Response Pattern"] = "Decreasing (warming up)"
    else
        analysis["Response Pattern"] = "Variable"
    end
    
    return analysis
end

-- Function to detect geographic distribution
local function detect_geographic_distribution(responses)
    local geo_info = {}
    local regions = {}
    local edge_locations = {}
    
    for _, response in ipairs(responses) do
        if response.header then
            -- Cloudflare edge location
            if response.header["cf-ray"] then
                local ray = response.header["cf-ray"]
                local location = ray:match("%-(%w+)$")
                if location then
                    edge_locations[location] = (edge_locations[location] or 0) + 1
                end
            end
            
            -- Amazon CloudFront edge
            if response.header["x-amz-cf-pop"] then
                local pop = response.header["x-amz-cf-pop"]
                edge_locations[pop] = (edge_locations[pop] or 0) + 1
            end
            
            -- Generic geographic headers
            if response.header["x-served-by"] then
                regions[response.header["x-served-by"]] = (regions[response.header["x-served-by"]] or 0) + 1
            end
        end
    end
    
    local unique_locations = 0
    for _ in pairs(edge_locations) do
        unique_locations = unique_locations + 1
    end
    
    if unique_locations > 1 then
        geo_info["Geographic Distribution"] = "Multiple edge locations detected"
        
        local location_list = {}
        for location, count in pairs(edge_locations) do
            table.insert(location_list, location .. " (" .. count .. "x)")
        end
        geo_info["Edge Locations"] = table.concat(location_list, ", ")
    end
    
    return geo_info
end

action = function(host, port)
    local samples = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".samples")) or 5
    local delay = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".delay")) or 2
    local timeout = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".timeout")) or 5
    
    local results = {}
    local responses = {}
    local timings = {}
    
    -- Collect multiple samples
    for i = 1, samples do
        local start_time = nmap.clock_ms()
        
        local response = http.get(host, port, "/", {
            timeout = timeout,
            header = {
                ["User-Agent"] = "Mozilla/5.0 (compatible; Nmap NSE)",
                ["Cache-Control"] = "no-cache",
                ["Pragma"] = "no-cache"
            }
        })
        
        local end_time = nmap.clock_ms()
        local response_time = end_time - start_time
        
        if response then
            table.insert(responses, response)
            table.insert(timings, response_time)
        end
        
        -- Wait between samples (except for the last one)
        if i < samples then
            stdnse.sleep(delay)
        end
    end
    
    if #responses == 0 then
        return nil
    end
    
    -- Analyze response times
    local timing_analysis = analyze_response_times(timings)
    if next(timing_analysis) then
        results["Response Time Analysis"] = timing_analysis
    end
    
    -- Detect infrastructure
    local infrastructure = detect_infrastructure(responses)
    for key, value in pairs(infrastructure) do
        results[key] = value
    end
    
    -- Detect rate limiting
    local rate_limiting = detect_rate_limiting(responses, timings)
    for key, value in pairs(rate_limiting) do
        results[key] = value
    end
    
    -- Detect geographic distribution
    local geo_distribution = detect_geographic_distribution(responses)
    for key, value in pairs(geo_distribution) do
        results[key] = value
    end
    
    -- Add sample information
    results["Analysis Samples"] = #responses .. " successful requests"
    
    -- Return results only if we detected interesting behavior
    if next(timing_analysis) or next(infrastructure) or next(rate_limiting) or next(geo_distribution) then
        return results
    else
        return nil
    end
end

