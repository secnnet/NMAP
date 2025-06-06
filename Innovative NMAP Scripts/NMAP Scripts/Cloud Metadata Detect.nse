local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"
local json = require "json"
local string = require "string"

description = [[
Detects cloud service metadata endpoints and attempts to identify the cloud provider
(AWS, Azure, GCP, DigitalOcean, etc.) by probing known metadata service URLs.
This script helps identify cloud-hosted services and their provider during reconnaissance.

WARNING: This script should only be used on systems you own or have explicit 
permission to test. Unauthorized scanning may violate terms of service.
]]

---
-- @usage
-- nmap --script cloud-metadata-detect -p 80,443,8080 <target>
-- nmap --script cloud-metadata-detect --script-args timeout=10 <target>
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | cloud-metadata-detect: 
-- |   Cloud Provider: Amazon Web Services (AWS)
-- |   Metadata Service: Available
-- |   Instance ID: i-1234567890abcdef0
-- |   Instance Type: t3.micro
-- |   Region: us-east-1
-- |   Security Groups: sg-12345678
-- |_  IAM Role: MyEC2Role
--
-- @args cloud-metadata-detect.timeout Timeout for HTTP requests (default: 5)
-- @args cloud-metadata-detect.useragent User agent string to use (default: nmap script)

author = "Bilel Graine"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "cloud"}

portrule = shortport.http

-- Cloud metadata service endpoints
local cloud_endpoints = {
    aws = {
        url = "http://169.254.169.254/latest/meta-data/",
        headers = {},
        indicators = {"instance-id", "instance-type", "placement"}
    },
    azure = {
        url = "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        headers = {["Metadata"] = "true"},
        indicators = {"compute", "network", "resourceGroupName"}
    },
    gcp = {
        url = "http://metadata.google.internal/computeMetadata/v1/",
        headers = {["Metadata-Flavor"] = "Google"},
        indicators = {"instance", "project"}
    },
    digitalocean = {
        url = "http://169.254.169.254/metadata/v1/",
        headers = {},
        indicators = {"droplet_id", "hostname", "region"}
    },
    alibaba = {
        url = "http://100.100.100.200/latest/meta-data/",
        headers = {},
        indicators = {"instance-id", "region-id", "zone-id"}
    }
}

-- Function to test cloud metadata endpoint
local function test_cloud_endpoint(host, port, provider, endpoint_info, timeout, useragent)
    local options = {
        timeout = timeout,
        header = endpoint_info.headers
    }
    
    if useragent then
        options.header["User-Agent"] = useragent
    end
    
    -- Try to access the metadata endpoint
    local response = http.get(host, port, endpoint_info.url, options)
    
    if not response or not response.status then
        return nil
    end
    
    -- Check if response indicates cloud metadata service
    if response.status == 200 and response.body then
        local body = response.body:lower()
        local indicator_count = 0
        
        for _, indicator in ipairs(endpoint_info.indicators) do
            if string.find(body, indicator:lower()) then
                indicator_count = indicator_count + 1
            end
        end
        
        -- If we found multiple indicators, likely a cloud metadata service
        if indicator_count >= 2 then
            return {
                provider = provider,
                response = response,
                confidence = indicator_count / #endpoint_info.indicators
            }
        end
    end
    
    return nil
end

-- Function to extract AWS metadata details
local function extract_aws_details(host, port, timeout, useragent)
    local details = {}
    local aws_endpoints = {
        "instance-id",
        "instance-type", 
        "placement/region",
        "placement/availability-zone",
        "security-groups",
        "iam/security-credentials/"
    }
    
    for _, endpoint in ipairs(aws_endpoints) do
        local url = "http://169.254.169.254/latest/meta-data/" .. endpoint
        local response = http.get(host, port, url, {timeout = timeout})
        
        if response and response.status == 200 and response.body then
            local key = endpoint:gsub("/", "_"):gsub("-", "_")
            details[key] = response.body:gsub("%s+", " "):gsub("^%s*(.-)%s*$", "%1")
        end
    end
    
    return details
end

-- Function to extract Azure metadata details
local function extract_azure_details(host, port, timeout, useragent)
    local details = {}
    local url = "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
    local options = {
        timeout = timeout,
        header = {["Metadata"] = "true"}
    }
    
    local response = http.get(host, port, url, options)
    
    if response and response.status == 200 and response.body then
        local status, parsed = pcall(json.parse, response.body)
        if status and parsed then
            if parsed.compute then
                details.vm_id = parsed.compute.vmId
                details.vm_size = parsed.compute.vmSize
                details.location = parsed.compute.location
                details.resource_group = parsed.compute.resourceGroupName
                details.subscription_id = parsed.compute.subscriptionId
            end
        end
    end
    
    return details
end

-- Function to extract GCP metadata details
local function extract_gcp_details(host, port, timeout, useragent)
    local details = {}
    local gcp_endpoints = {
        "instance/id",
        "instance/machine-type",
        "instance/zone",
        "project/project-id"
    }
    
    for _, endpoint in ipairs(gcp_endpoints) do
        local url = "http://metadata.google.internal/computeMetadata/v1/" .. endpoint
        local options = {
            timeout = timeout,
            header = {["Metadata-Flavor"] = "Google"}
        }
        
        local response = http.get(host, port, url, options)
        
        if response and response.status == 200 and response.body then
            local key = endpoint:gsub("/", "_"):gsub("-", "_")
            details[key] = response.body:gsub("%s+", " "):gsub("^%s*(.-)%s*$", "%1")
        end
    end
    
    return details
end

action = function(host, port)
    local timeout = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".timeout")) or 5
    local useragent = stdnse.get_script_args(SCRIPT_NAME .. ".useragent")
    
    local results = {}
    local detected_provider = nil
    local highest_confidence = 0
    
    -- Test each cloud provider endpoint
    for provider, endpoint_info in pairs(cloud_endpoints) do
        local result = test_cloud_endpoint(host, port, provider, endpoint_info, timeout, useragent)
        
        if result and result.confidence > highest_confidence then
            highest_confidence = result.confidence
            detected_provider = provider
        end
    end
    
    if not detected_provider then
        return nil
    end
    
    -- Extract detailed information based on detected provider
    local details = {}
    
    if detected_provider == "aws" then
        results["Cloud Provider"] = "Amazon Web Services (AWS)"
        details = extract_aws_details(host, port, timeout, useragent)
        
        if details.instance_id then
            results["Instance ID"] = details.instance_id
        end
        if details.instance_type then
            results["Instance Type"] = details.instance_type
        end
        if details.placement_region then
            results["Region"] = details.placement_region
        end
        if details.placement_availability_zone then
            results["Availability Zone"] = details.placement_availability_zone
        end
        if details.security_groups then
            results["Security Groups"] = details.security_groups
        end
        if details.iam_security_credentials_ then
            results["IAM Roles Available"] = "Yes"
        end
        
    elseif detected_provider == "azure" then
        results["Cloud Provider"] = "Microsoft Azure"
        details = extract_azure_details(host, port, timeout, useragent)
        
        if details.vm_id then
            results["VM ID"] = details.vm_id
        end
        if details.vm_size then
            results["VM Size"] = details.vm_size
        end
        if details.location then
            results["Location"] = details.location
        end
        if details.resource_group then
            results["Resource Group"] = details.resource_group
        end
        if details.subscription_id then
            results["Subscription ID"] = details.subscription_id
        end
        
    elseif detected_provider == "gcp" then
        results["Cloud Provider"] = "Google Cloud Platform (GCP)"
        details = extract_gcp_details(host, port, timeout, useragent)
        
        if details.instance_id then
            results["Instance ID"] = details.instance_id
        end
        if details.instance_machine_type then
            results["Machine Type"] = details.instance_machine_type:match("([^/]+)$")
        end
        if details.instance_zone then
            results["Zone"] = details.instance_zone:match("([^/]+)$")
        end
        if details.project_project_id then
            results["Project ID"] = details.project_project_id
        end
        
    elseif detected_provider == "digitalocean" then
        results["Cloud Provider"] = "DigitalOcean"
        
    elseif detected_provider == "alibaba" then
        results["Cloud Provider"] = "Alibaba Cloud"
    end
    
    results["Metadata Service"] = "Available"
    results["Detection Confidence"] = string.format("%.0f%%", highest_confidence * 100)
    
    return results
end

