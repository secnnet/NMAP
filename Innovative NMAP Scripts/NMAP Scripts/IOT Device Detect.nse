local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"
local string = require "string"
local table = require "table"

description = [[
Detects IoT devices by analyzing device-specific HTTP headers, response patterns,
default web interfaces, and known IoT device signatures. This script identifies
smart home devices, industrial IoT, security cameras, routers, and other
connected devices.

WARNING: This script should only be used on systems you own or have explicit 
permission to test. Unauthorized scanning may violate terms of service.
]]

---
-- @usage
-- nmap --script iot-device-detect -p 80,443,8080,8081,8443 <target>
-- nmap --script iot-device-detect --script-args deep-probe=true <target>
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | iot-device-detect: 
-- |   Device Type: IP Camera
-- |   Manufacturer: Hikvision
-- |   Model: DS-2CD2142FWD-I
-- |   Firmware Version: V5.4.5
-- |   Default Credentials: Possible (admin/12345)
-- |   Web Interface: /doc/page/login.asp
-- |   Device Features: Night Vision, Motion Detection, Audio
-- |_  Security Status: Default credentials detected
--
-- @args iot-device-detect.deep-probe Perform deep device analysis (default: false)
-- @args iot-device-detect.timeout Timeout for HTTP requests (default: 5)

author = "Bilel Graine"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "version"}

portrule = shortport.http

-- IoT device signatures
local iot_signatures = {
    -- IP Cameras
    hikvision = {
        headers = {"server.*hikvision", "www%-authenticate.*hikvision"},
        content = {"hikvision", "/doc/page/login%.asp", "dvr web client"},
        paths = {"/doc/page/login.asp", "/ISAPI/System/deviceInfo"},
        device_type = "IP Camera",
        manufacturer = "Hikvision"
    },
    dahua = {
        headers = {"server.*dahua", "www%-authenticate.*dahua"},
        content = {"dahua", "dh_mobile", "/current_config"},
        paths = {"/current_config", "/cgi-bin/main-cgi"},
        device_type = "IP Camera",
        manufacturer = "Dahua"
    },
    axis = {
        headers = {"server.*axis"},
        content = {"axis", "vapix", "/axis%-cgi/"},
        paths = {"/axis-cgi/param.cgi", "/view/index.shtml"},
        device_type = "IP Camera",
        manufacturer = "Axis"
    },
    
    -- Smart Home Devices
    nest = {
        headers = {"server.*nest"},
        content = {"nest", "nest%.com", "nest thermostat"},
        paths = {"/api/0.1/user", "/mobile/user.login"},
        device_type = "Smart Thermostat",
        manufacturer = "Google Nest"
    },
    philips_hue = {
        headers = {"server.*philips"},
        content = {"philips hue", "hue bridge", "/api/.*lights"},
        paths = {"/api", "/description.xml"},
        device_type = "Smart Light Hub",
        manufacturer = "Philips"
    },
    
    -- Routers and Network Equipment
    linksys = {
        headers = {"server.*linksys"},
        content = {"linksys", "smart wi%-fi", "ea6500"},
        paths = {"/JNAP/", "/ui/", "/sysinfo.cgi"},
        device_type = "Wireless Router",
        manufacturer = "Linksys"
    },
    netgear = {
        headers = {"server.*netgear"},
        content = {"netgear", "genie", "readynas"},
        paths = {"/api/1.0/", "/currentsetting.htm"},
        device_type = "Router/NAS",
        manufacturer = "Netgear"
    },
    dlink = {
        headers = {"server.*d%-link"},
        content = {"d%-link", "dir%-", "dcs%-"},
        paths = {"/common_page/login.xml", "/cgi-bin/webproc"},
        device_type = "Network Device",
        manufacturer = "D-Link"
    },
    
    -- Industrial IoT
    siemens = {
        headers = {"server.*siemens"},
        content = {"siemens", "simatic", "s7%-"},
        paths = {"/Portal/Portal.mwsl", "/awp/"},
        device_type = "Industrial Controller",
        manufacturer = "Siemens"
    },
    schneider = {
        headers = {"server.*schneider"},
        content = {"schneider", "modicon", "unity"},
        paths = {"/secure/system.htm", "/config/"},
        device_type = "Industrial Controller",
        manufacturer = "Schneider Electric"
    },
    
    -- Printers
    hp_printer = {
        headers = {"server.*hp"},
        content = {"hp", "laserjet", "officejet", "embedded web server"},
        paths = {"/hp/device/info_deviceStatus.xml", "/DevMgmt/"},
        device_type = "Printer",
        manufacturer = "HP"
    },
    canon_printer = {
        headers = {"server.*canon"},
        content = {"canon", "pixma", "imagerunner"},
        paths = {"/English/pages_MacUS/", "/airprint/"},
        device_type = "Printer",
        manufacturer = "Canon"
    },
    
    -- NAS Devices
    synology = {
        headers = {"server.*synology"},
        content = {"synology", "diskstation", "dsm"},
        paths = {"/webapi/", "/webman/"},
        device_type = "NAS",
        manufacturer = "Synology"
    },
    qnap = {
        headers = {"server.*qnap"},
        content = {"qnap", "turbo nas", "qts"},
        paths = {"/cgi-bin/", "/QTS/"},
        device_type = "NAS",
        manufacturer = "QNAP"
    }
}

-- Common IoT default credentials
local default_credentials = {
    {"admin", "admin"},
    {"admin", "password"},
    {"admin", "12345"},
    {"admin", ""},
    {"root", "root"},
    {"root", "admin"},
    {"user", "user"},
    {"guest", "guest"},
    {"admin", "1234"},
    {"admin", "admin123"}
}

-- Function to check for IoT device signatures
local function check_iot_signatures(host, port, timeout)
    local detected_devices = {}
    
    -- Get main page
    local response = http.get(host, port, "/", {timeout = timeout})
    
    if not response then
        return detected_devices
    end
    
    local content = (response.body or ""):lower()
    local headers = response.header or {}
    
    for device_id, signature in pairs(iot_signatures) do
        local score = 0
        local matches = {}
        
        -- Check headers
        if signature.headers then
            for header_name, header_value in pairs(headers) do
                local header_string = (header_name .. ": " .. (header_value or "")):lower()
                
                for _, pattern in ipairs(signature.headers) do
                    if string.find(header_string, pattern:lower()) then
                        score = score + 2
                        table.insert(matches, "header: " .. pattern)
                    end
                end
            end
        end
        
        -- Check content
        if signature.content then
            for _, pattern in ipairs(signature.content) do
                if string.find(content, pattern:lower()) then
                    score = score + 1
                    table.insert(matches, "content: " .. pattern)
                end
            end
        end
        
        -- Check specific paths
        if signature.paths then
            for _, path in ipairs(signature.paths) do
                local path_response = http.get(host, port, path, {timeout = timeout})
                
                if path_response and (path_response.status == 200 or path_response.status == 401) then
                    score = score + 3
                    table.insert(matches, "path: " .. path)
                end
            end
        end
        
        -- If we have a good confidence score, add to detected devices
        if score >= 2 then
            detected_devices[device_id] = {
                signature = signature,
                score = score,
                matches = matches
            }
        end
    end
    
    return detected_devices
end

-- Function to extract device information
local function extract_device_info(host, port, device_id, signature, timeout)
    local info = {}
    
    -- Try to get device-specific information
    if signature.paths then
        for _, path in ipairs(signature.paths) do
            local response = http.get(host, port, path, {timeout = timeout})
            
            if response and response.status == 200 and response.body then
                local body = response.body
                
                -- Extract common device information patterns
                local version_patterns = {
                    "version[\"']?:?[\"']?([%d%.]+)",
                    "firmware[\"']?:?[\"']?([%d%.]+)",
                    "software[\"']?:?[\"']?([%d%.]+)",
                    "v([%d%.]+)",
                    "ver%.?([%d%.]+)"
                }
                
                for _, pattern in ipairs(version_patterns) do
                    local version = body:match(pattern)
                    if version then
                        info["Firmware Version"] = version
                        break
                    end
                end
                
                -- Extract model information
                local model_patterns = {
                    "model[\"']?:?[\"']?([%w%-]+)",
                    "device[\"']?:?[\"']?([%w%-]+)",
                    "product[\"']?:?[\"']?([%w%-]+)"
                }
                
                for _, pattern in ipairs(model_patterns) do
                    local model = body:match(pattern)
                    if model then
                        info["Model"] = model
                        break
                    end
                end
                
                -- Extract serial number
                local serial = body:match("serial[\"']?:?[\"']?([%w%-]+)")
                if serial then
                    info["Serial Number"] = serial
                end
                
                -- Extract MAC address
                local mac = body:match("([%x][%x]:[%x][%x]:[%x][%x]:[%x][%x]:[%x][%x]:[%x][%x])")
                if mac then
                    info["MAC Address"] = mac
                end
            end
        end
    end
    
    return info
end

-- Function to test for default credentials
local function test_default_credentials(host, port, timeout)
    local vulnerable_creds = {}
    
    -- Common login paths
    local login_paths = {
        "/",
        "/login",
        "/admin",
        "/cgi-bin/webproc",
        "/doc/page/login.asp"
    }
    
    for _, path in ipairs(login_paths) do
        local response = http.get(host, port, path, {timeout = timeout})
        
        if response and response.status == 401 then
            -- Try a few common default credentials
            for i = 1, math.min(3, #default_credentials) do
                local username, password = default_credentials[i][1], default_credentials[i][2]
                
                local auth_response = http.get(host, port, path, {
                    timeout = timeout,
                    auth = {
                        username = username,
                        password = password
                    }
                })
                
                if auth_response and auth_response.status == 200 then
                    table.insert(vulnerable_creds, username .. "/" .. password)
                end
            end
            
            break
        end
    end
    
    return vulnerable_creds
end

-- Function to perform deep device analysis
local function deep_device_analysis(host, port, device_id, signature, timeout)
    local analysis = {}
    
    -- Check for common IoT vulnerabilities
    local vuln_paths = {
        "/cgi-bin/webproc?getpage=../../../etc/passwd&var:page=deviceinfo",
        "/HNAP1/",
        "/setup.cgi?next_file=netgear.cfg&todo=syscmd&cmd=rm+-rf+/tmp/*;wget+http://",
        "/cgi-bin/luci/admin/system/admin"
    }
    
    for _, path in ipairs(vuln_paths) do
        local response = http.get(host, port, path, {timeout = timeout})
        
        if response and response.status == 200 and response.body then
            if string.find(response.body:lower(), "root:") then
                analysis["Vulnerability"] = "Directory traversal possible"
            elseif string.find(response.body:lower(), "hnap") then
                analysis["HNAP Protocol"] = "Detected"
            end
        end
    end
    
    -- Check for exposed configuration files
    local config_paths = {
        "/config.xml",
        "/backup.cfg",
        "/system.cfg",
        "/settings.ini"
    }
    
    for _, path in ipairs(config_paths) do
        local response = http.get(host, port, path, {timeout = timeout})
        
        if response and response.status == 200 then
            analysis["Exposed Config"] = path
            break
        end
    end
    
    return analysis
end

action = function(host, port)
    local timeout = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".timeout")) or 5
    local deep_probe = stdnse.get_script_args(SCRIPT_NAME .. ".deep-probe")
    
    local results = {}
    
    -- Detect IoT devices
    local detected_devices = check_iot_signatures(host, port, timeout)
    
    if not next(detected_devices) then
        return nil
    end
    
    -- Process the highest scoring device
    local best_device = nil
    local highest_score = 0
    
    for device_id, detection_info in pairs(detected_devices) do
        if detection_info.score > highest_score then
            highest_score = detection_info.score
            best_device = device_id
        end
    end
    
    if best_device then
        local signature = detected_devices[best_device].signature
        
        results["Device Type"] = signature.device_type
        results["Manufacturer"] = signature.manufacturer
        results["Detection Confidence"] = string.format("%.0f%%", (highest_score / 6) * 100)
        
        -- Extract detailed device information
        local device_info = extract_device_info(host, port, best_device, signature, timeout)
        for key, value in pairs(device_info) do
            results[key] = value
        end
        
        -- Test for default credentials
        local vulnerable_creds = test_default_credentials(host, port, timeout)
        if #vulnerable_creds > 0 then
            results["Default Credentials"] = "Detected (" .. table.concat(vulnerable_creds, ", ") .. ")"
            results["Security Status"] = "Default credentials detected"
        end
        
        -- Perform deep analysis if requested
        if deep_probe then
            local analysis = deep_device_analysis(host, port, best_device, signature, timeout)
            for key, value in pairs(analysis) do
                results[key] = value
            end
        end
        
        -- Add detection details
        local matches = detected_devices[best_device].matches
        if #matches > 0 then
            results["Detection Matches"] = table.concat(matches, ", ")
        end
    end
    
    return results
end

