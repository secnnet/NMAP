local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"
local string = require "string"
local table = require "table"

description = [[
Detects Docker containers and Kubernetes pods by analyzing HTTP headers, 
response patterns, and container-specific endpoints. This script identifies
containerized applications and attempts to gather container orchestration
information.

WARNING: This script should only be used on systems you own or have explicit 
permission to test. Unauthorized scanning may violate terms of service.
]]

---
-- @usage
-- nmap --script container-detect -p 80,443,8080,2375,2376 <target>
-- nmap --script container-detect --script-args deep-scan=true <target>
--
-- @output
-- PORT     STATE SERVICE
-- 8080/tcp open  http-proxy
-- | container-detect: 
-- |   Container Technology: Docker
-- |   Container ID: a1b2c3d4e5f6
-- |   Image: nginx:latest
-- |   Orchestration: Kubernetes
-- |   Pod Name: web-server-pod-12345
-- |   Namespace: production
-- |   Service Account: default
-- |_  Cluster: my-k8s-cluster
--
-- @args container-detect.deep-scan Perform deep container analysis (default: false)
-- @args container-detect.timeout Timeout for HTTP requests (default: 5)

author = "Bilel Graine"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "version"}

portrule = shortport.port_or_service({80, 443, 2375, 2376, 8080, 8443, 9090, 10250}, {"http", "https", "docker", "kubelet"})

-- Container indicators in HTTP headers
local container_headers = {
    docker = {
        "x-docker-",
        "docker-content-digest",
        "docker-distribution-api-version"
    },
    kubernetes = {
        "x-kubernetes-",
        "x-k8s-",
        "kubernetes-"
    },
    containerd = {
        "x-containerd-",
        "containerd-"
    }
}

-- Container-specific endpoints to probe
local container_endpoints = {
    docker = {
        "/v1.24/info",
        "/version",
        "/info",
        "/_ping",
        "/containers/json"
    },
    kubernetes = {
        "/api/v1",
        "/healthz",
        "/metrics",
        "/version",
        "/api/v1/namespaces",
        "/api/v1/pods"
    },
    kubelet = {
        "/stats/summary",
        "/pods",
        "/spec",
        "/healthz"
    }
}

-- Function to check for container headers
local function check_container_headers(headers)
    local detected = {}
    
    if not headers then
        return detected
    end
    
    for header_name, header_value in pairs(headers) do
        local header_lower = header_name:lower()
        
        for container_type, indicators in pairs(container_headers) do
            for _, indicator in ipairs(indicators) do
                if string.find(header_lower, indicator:lower()) then
                    detected[container_type] = true
                end
            end
        end
    end
    
    return detected
end

-- Function to probe container endpoints
local function probe_container_endpoints(host, port, timeout)
    local detected = {}
    
    for container_type, endpoints in pairs(container_endpoints) do
        for _, endpoint in ipairs(endpoints) do
            local response = http.get(host, port, endpoint, {timeout = timeout})
            
            if response and response.status then
                if response.status == 200 or response.status == 401 or response.status == 403 then
                    detected[container_type] = {
                        endpoint = endpoint,
                        status = response.status,
                        response = response
                    }
                    break
                end
            end
        end
    end
    
    return detected
end

-- Function to extract Docker information
local function extract_docker_info(host, port, timeout)
    local info = {}
    
    -- Try Docker API endpoints
    local endpoints = {"/version", "/info", "/_ping"}
    
    for _, endpoint in ipairs(endpoints) do
        local response = http.get(host, port, endpoint, {timeout = timeout})
        
        if response and response.status == 200 and response.body then
            if endpoint == "/version" then
                -- Parse Docker version info
                local version_match = response.body:match('"Version":"([^"]+)"')
                if version_match then
                    info["Docker Version"] = version_match
                end
                
                local api_version = response.body:match('"ApiVersion":"([^"]+)"')
                if api_version then
                    info["API Version"] = api_version
                end
                
            elseif endpoint == "/info" then
                -- Parse Docker system info
                local containers = response.body:match('"Containers":(%d+)')
                if containers then
                    info["Total Containers"] = containers
                end
                
                local images = response.body:match('"Images":(%d+)')
                if images then
                    info["Total Images"] = images
                end
                
                local driver = response.body:match('"Driver":"([^"]+)"')
                if driver then
                    info["Storage Driver"] = driver
                end
            end
        end
    end
    
    return info
end

-- Function to extract Kubernetes information
local function extract_kubernetes_info(host, port, timeout)
    local info = {}
    
    -- Try Kubernetes API endpoints
    local response = http.get(host, port, "/version", {timeout = timeout})
    
    if response and response.status == 200 and response.body then
        local version = response.body:match('"gitVersion":"([^"]+)"')
        if version then
            info["Kubernetes Version"] = version
        end
        
        local platform = response.body:match('"platform":"([^"]+)"')
        if platform then
            info["Platform"] = platform
        end
    end
    
    -- Check for kubelet
    local kubelet_response = http.get(host, port, "/healthz", {timeout = timeout})
    if kubelet_response and kubelet_response.status == 200 then
        info["Service Type"] = "Kubelet"
    end
    
    return info
end

-- Function to detect container environment variables
local function detect_container_env(response_body)
    local env_indicators = {}
    
    if not response_body then
        return env_indicators
    end
    
    local body_lower = response_body:lower()
    
    -- Look for common container environment variables
    local patterns = {
        "hostname.*pod.*",
        "kubernetes_service_host",
        "kubernetes_port",
        "docker_container",
        "container_id",
        "pod_name",
        "pod_namespace"
    }
    
    for _, pattern in ipairs(patterns) do
        if string.find(body_lower, pattern) then
            table.insert(env_indicators, pattern)
        end
    end
    
    return env_indicators
end

-- Function to perform deep container analysis
local function deep_container_analysis(host, port, timeout)
    local analysis = {}
    
    -- Check for container-specific files and directories
    local probe_paths = {
        "/.dockerenv",
        "/proc/1/cgroup",
        "/var/run/secrets/kubernetes.io/serviceaccount/token",
        "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
    }
    
    for _, path in ipairs(probe_paths) do
        local response = http.get(host, port, path, {timeout = timeout})
        
        if response and response.status == 200 then
            if path == "/.dockerenv" then
                analysis["Docker Environment"] = "Detected"
            elseif string.find(path, "kubernetes") then
                analysis["Kubernetes Service Account"] = "Detected"
                
                if string.find(path, "namespace") and response.body then
                    analysis["Kubernetes Namespace"] = response.body:gsub("%s+", "")
                end
            elseif path == "/proc/1/cgroup" and response.body then
                if string.find(response.body:lower(), "docker") then
                    analysis["Container Runtime"] = "Docker"
                elseif string.find(response.body:lower(), "containerd") then
                    analysis["Container Runtime"] = "containerd"
                end
            end
        end
    end
    
    return analysis
end

action = function(host, port)
    local timeout = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".timeout")) or 5
    local deep_scan = stdnse.get_script_args(SCRIPT_NAME .. ".deep-scan")
    
    local results = {}
    local container_detected = false
    
    -- First, try a basic HTTP request to get headers
    local response = http.get(host, port, "/", {timeout = timeout})
    
    if response then
        -- Check headers for container indicators
        local header_detection = check_container_headers(response.header)
        
        for container_type, _ in pairs(header_detection) do
            container_detected = true
            results["Container Technology"] = container_type:upper()
        end
        
        -- Check response body for environment indicators
        local env_indicators = detect_container_env(response.body)
        if #env_indicators > 0 then
            container_detected = true
            results["Environment Indicators"] = table.concat(env_indicators, ", ")
        end
    end
    
    -- Probe container-specific endpoints
    local endpoint_detection = probe_container_endpoints(host, port, timeout)
    
    for container_type, detection_info in pairs(endpoint_detection) do
        container_detected = true
        
        if container_type == "docker" then
            results["Container Technology"] = "Docker"
            results["Docker API"] = "Available (" .. detection_info.endpoint .. ")"
            
            -- Extract Docker-specific information
            local docker_info = extract_docker_info(host, port, timeout)
            for key, value in pairs(docker_info) do
                results[key] = value
            end
            
        elseif container_type == "kubernetes" then
            results["Orchestration"] = "Kubernetes"
            results["Kubernetes API"] = "Available (" .. detection_info.endpoint .. ")"
            
            -- Extract Kubernetes-specific information
            local k8s_info = extract_kubernetes_info(host, port, timeout)
            for key, value in pairs(k8s_info) do
                results[key] = value
            end
            
        elseif container_type == "kubelet" then
            results["Service Type"] = "Kubelet"
            results["Kubelet API"] = "Available (" .. detection_info.endpoint .. ")"
        end
    end
    
    -- Perform deep analysis if requested
    if deep_scan and container_detected then
        local deep_analysis = deep_container_analysis(host, port, timeout)
        for key, value in pairs(deep_analysis) do
            results[key] = value
        end
    end
    
    -- Return results only if container technology was detected
    if container_detected then
        return results
    else
        return nil
    end
end

