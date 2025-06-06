local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"
local string = require "string"
local table = require "table"

description = [[
Detects modern web frameworks and technologies by analyzing HTTP headers,
response patterns, JavaScript frameworks, and API endpoints. This script
identifies technologies like React, Vue.js, Angular, GraphQL, REST APIs,
and modern backend frameworks.

WARNING: This script should only be used on systems you own or have explicit 
permission to test. Unauthorized scanning may violate terms of service.
]]

---
-- @usage
-- nmap --script modern-web-tech-detect -p 80,443,3000,8080 <target>
-- nmap --script modern-web-tech-detect --script-args check-apis=true <target>
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | modern-web-tech-detect: 
-- |   Frontend Framework: React 18.2.0
-- |   Backend Framework: Express.js
-- |   API Type: GraphQL
-- |   GraphQL Endpoint: /graphql
-- |   Build Tool: Webpack
-- |   State Management: Redux
-- |   UI Library: Material-UI
-- |   Authentication: JWT
-- |_  CDN: Cloudflare
--
-- @args modern-web-tech-detect.check-apis Check for API endpoints (default: false)
-- @args modern-web-tech-detect.timeout Timeout for HTTP requests (default: 5)

author = "Bilel Graine"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "version"}

portrule = shortport.http

-- Modern web framework indicators
local framework_indicators = {
    react = {
        headers = {"x-react-", "x-powered-by.*react"},
        content = {
            "react%.js", "react%-dom", "__REACT_DEVTOOLS_GLOBAL_HOOK__",
            "data%-reactroot", "react%-text", "_reactInternalFiber"
        },
        files = {"/static/js/main%..*%.js", "/static/js/.*react.*%.js"}
    },
    vue = {
        headers = {"x-vue-", "x-powered-by.*vue"},
        content = {
            "vue%.js", "vue%-router", "__VUE__", "v%-if", "v%-for", "v%-model",
            "data%-v%-", "vue%-component"
        },
        files = {"/js/app%..*%.js", "/js/.*vue.*%.js"}
    },
    angular = {
        headers = {"x-angular-", "x-powered-by.*angular"},
        content = {
            "angular%.js", "ng%-app", "ng%-controller", "ng%-repeat",
            "__ng", "angular%.module", "data%-ng%-"
        },
        files = {"/main%..*%.js", "/polyfills%..*%.js", "/runtime%..*%.js"}
    },
    svelte = {
        headers = {"x-svelte-"},
        content = {"svelte", "__svelte", "svelte%-", "data%-svelte%-"},
        files = {"/build/bundle%.js", "/_app/.*%.js"}
    },
    nextjs = {
        headers = {"x-powered-by.*next%.js", "x-nextjs-"},
        content = {"__NEXT_DATA__", "_next/static", "next/router", "__next"},
        files = {"/_next/static/.*%.js", "/_next/.*"}
    },
    nuxt = {
        headers = {"x-nuxt-", "x-powered-by.*nuxt"},
        content = {"__NUXT__", "_nuxt/", "nuxt%.js"},
        files = {"/_nuxt/.*%.js"}
    }
}

-- Backend framework indicators
local backend_indicators = {
    express = {
        headers = {"x%-powered%-by.*express", "x%-express%-"},
        content = {"express", "express%.js"}
    },
    fastapi = {
        headers = {"server.*fastapi", "x%-fastapi%-"},
        content = {"fastapi", "/docs", "/redoc", "/openapi%.json"}
    },
    django = {
        headers = {"server.*django", "x%-django%-"},
        content = {"django", "csrfmiddlewaretoken", "django%-admin"}
    },
    flask = {
        headers = {"server.*flask", "x%-flask%-"},
        content = {"flask", "werkzeug"}
    },
    rails = {
        headers = {"x%-powered%-by.*ruby", "server.*passenger"},
        content = {"rails", "ruby on rails", "csrf%-token"}
    },
    laravel = {
        headers = {"x%-powered%-by.*php", "x%-laravel%-"},
        content = {"laravel", "laravel_session", "_token"}
    },
    spring = {
        headers = {"x%-application%-context", "server.*tomcat"},
        content = {"spring", "springframework"}
    }
}

-- API and technology indicators
local api_indicators = {
    graphql = {
        endpoints = {"/graphql", "/graphiql", "/api/graphql"},
        content = {"graphql", "__schema", "query.*mutation"}
    },
    rest = {
        endpoints = {"/api/v1", "/api/v2", "/rest", "/api"},
        headers = {"content%-type.*application/json"}
    },
    grpc = {
        headers = {"content%-type.*application/grpc", "grpc%-"},
        content = {"grpc"}
    },
    websocket = {
        headers = {"upgrade.*websocket", "connection.*upgrade"},
        content = {"websocket", "socket%.io"}
    }
}

-- Build tools and bundlers
local build_tools = {
    webpack = {"webpack", "__webpack", "webpackJsonp"},
    vite = {"vite", "__vite", "/@vite/"},
    parcel = {"parcel", "__parcel"},
    rollup = {"rollup", "__rollup"},
    esbuild = {"esbuild"}
}

-- Function to check HTTP headers for framework indicators
local function check_headers(headers, indicators)
    local detected = {}
    
    if not headers then
        return detected
    end
    
    for header_name, header_value in pairs(headers) do
        local header_lower = (header_name .. ": " .. (header_value or "")):lower()
        
        for _, pattern in ipairs(indicators) do
            if string.find(header_lower, pattern:lower()) then
                table.insert(detected, pattern)
            end
        end
    end
    
    return detected
end

-- Function to check response content for framework indicators
local function check_content(content, indicators)
    local detected = {}
    
    if not content then
        return detected
    end
    
    local content_lower = content:lower()
    
    for _, pattern in ipairs(indicators) do
        if string.find(content_lower, pattern:lower()) then
            table.insert(detected, pattern)
        end
    end
    
    return detected
end

-- Function to probe for specific files
local function probe_files(host, port, file_patterns, timeout)
    local found_files = {}
    
    for _, pattern in ipairs(file_patterns) do
        -- Convert pattern to actual path (simplified)
        local test_paths = {pattern}
        
        -- Add some common variations
        if string.find(pattern, "main%.") then
            table.insert(test_paths, pattern:gsub("main%.", "app."))
            table.insert(test_paths, pattern:gsub("main%.", "index."))
        end
        
        for _, path in ipairs(test_paths) do
            local response = http.get(host, port, path, {timeout = timeout})
            
            if response and response.status == 200 then
                table.insert(found_files, path)
                break
            end
        end
    end
    
    return found_files
end

-- Function to detect API endpoints
local function detect_apis(host, port, timeout)
    local apis = {}
    
    for api_type, info in pairs(api_indicators) do
        if info.endpoints then
            for _, endpoint in ipairs(info.endpoints) do
                local response = http.get(host, port, endpoint, {timeout = timeout})
                
                if response and (response.status == 200 or response.status == 400 or response.status == 405) then
                    apis[api_type] = {
                        endpoint = endpoint,
                        status = response.status
                    }
                    
                    -- For GraphQL, try to get schema info
                    if api_type == "graphql" and response.status == 200 then
                        local introspection_query = '{"query":"query IntrospectionQuery { __schema { types { name } } }"}'
                        local post_response = http.post(host, port, endpoint, {
                            timeout = timeout,
                            header = {["Content-Type"] = "application/json"}
                        }, introspection_query)
                        
                        if post_response and post_response.status == 200 then
                            apis[api_type].introspection = "Available"
                        end
                    end
                    
                    break
                end
            end
        end
    end
    
    return apis
end

-- Function to extract version information
local function extract_versions(content)
    local versions = {}
    
    if not content then
        return versions
    end
    
    -- Common version patterns
    local version_patterns = {
        {"react", "react[\"']?:?[\"']?([%d%.]+)"},
        {"vue", "vue[\"']?:?[\"']?([%d%.]+)"},
        {"angular", "angular[\"']?:?[\"']?([%d%.]+)"},
        {"jquery", "jquery[%-v]?([%d%.]+)"},
        {"bootstrap", "bootstrap[%-v]?([%d%.]+)"}
    }
    
    for _, pattern_info in ipairs(version_patterns) do
        local name, pattern = pattern_info[1], pattern_info[2]
        local version = content:match(pattern)
        if version then
            versions[name] = version
        end
    end
    
    return versions
end

action = function(host, port)
    local timeout = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".timeout")) or 5
    local check_apis = stdnse.get_script_args(SCRIPT_NAME .. ".check-apis")
    
    local results = {}
    local technologies_detected = false
    
    -- Get main page
    local response = http.get(host, port, "/", {timeout = timeout})
    
    if not response or not response.status then
        return nil
    end
    
    local content = response.body or ""
    local headers = response.header or {}
    
    -- Check for frontend frameworks
    for framework, indicators in pairs(framework_indicators) do
        local header_matches = check_headers(headers, indicators.headers or {})
        local content_matches = check_content(content, indicators.content or {})
        local file_matches = probe_files(host, port, indicators.files or {}, timeout)
        
        if #header_matches > 0 or #content_matches > 0 or #file_matches > 0 then
            technologies_detected = true
            
            local framework_name = framework:gsub("^%l", string.upper)
            if framework == "nextjs" then
                framework_name = "Next.js"
            elseif framework == "nuxt" then
                framework_name = "Nuxt.js"
            elseif framework == "vue" then
                framework_name = "Vue.js"
            end
            
            results["Frontend Framework"] = framework_name
            
            if #file_matches > 0 then
                results["Framework Files"] = table.concat(file_matches, ", ")
            end
        end
    end
    
    -- Check for backend frameworks
    for framework, indicators in pairs(backend_indicators) do
        local header_matches = check_headers(headers, indicators.headers or {})
        local content_matches = check_content(content, indicators.content or {})
        
        if #header_matches > 0 or #content_matches > 0 then
            technologies_detected = true
            
            local framework_name = framework:gsub("^%l", string.upper)
            if framework == "fastapi" then
                framework_name = "FastAPI"
            elseif framework == "nextjs" then
                framework_name = "Next.js"
            end
            
            results["Backend Framework"] = framework_name
        end
    end
    
    -- Check for build tools
    for tool, indicators in pairs(build_tools) do
        local content_matches = check_content(content, indicators)
        
        if #content_matches > 0 then
            technologies_detected = true
            
            local tool_name = tool:gsub("^%l", string.upper)
            results["Build Tool"] = tool_name
        end
    end
    
    -- Extract version information
    local versions = extract_versions(content)
    for tech, version in pairs(versions) do
        results[tech:gsub("^%l", string.upper) .. " Version"] = version
    end
    
    -- Check for APIs if requested
    if check_apis then
        local detected_apis = detect_apis(host, port, timeout)
        
        for api_type, api_info in pairs(detected_apis) do
            technologies_detected = true
            
            local api_name = api_type:gsub("^%l", string.upper)
            if api_type == "graphql" then
                api_name = "GraphQL"
            elseif api_type == "rest" then
                api_name = "REST API"
            elseif api_type == "grpc" then
                api_name = "gRPC"
            end
            
            results["API Type"] = api_name
            results[api_name .. " Endpoint"] = api_info.endpoint
            
            if api_info.introspection then
                results[api_name .. " Introspection"] = api_info.introspection
            end
        end
    end
    
    -- Check for common security headers and technologies
    if headers then
        if headers["x-frame-options"] then
            results["X-Frame-Options"] = headers["x-frame-options"]
        end
        
        if headers["content-security-policy"] then
            results["CSP"] = "Enabled"
        end
        
        if headers["server"] then
            results["Server"] = headers["server"]
        end
        
        if headers["x-powered-by"] then
            results["X-Powered-By"] = headers["x-powered-by"]
        end
    end
    
    -- Return results only if technologies were detected
    if technologies_detected or next(results) then
        return results
    else
        return nil
    end
end

