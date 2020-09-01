require "config"
local match = string.match
local ngxmatch = ngx.re.match
local unescape = ngx.unescape_uri
local get_headers = ngx.req.get_headers
local optionIsOn = function(options)
    return options == "on" and true or false
end
logpath = logdir
rulepath = RulePath
UrlDeny = optionIsOn(UrlDeny)
PostCheck = optionIsOn(postMatch)
CookieCheck = optionIsOn(cookieMatch)
WhiteCheck = optionIsOn(whiteModule)
PathInfoFix = optionIsOn(PathInfoFix)
attacklog = optionIsOn(attacklog)
CCDeny = optionIsOn(CCDeny)
Redirect = optionIsOn(Redirect)
function getClientIp()
    IP = ngx.var.remote_addr
    if IP == nil then
        IP = "unknown"
    end
    return IP
end

-- 写入日志文件
function write(logfile, msg)
    local fd = io.open(logfile, "ab")
    if fd == nil then
        return
    end
    fd:write(msg)
    fd:flush()
    fd:close()
end

-- format log line and write log
function log(method, url, data, ruletag)
    if attacklog then
        local realIp = getClientIp()
        local ua = ngx.var.http_user_agent
        local servername = ngx.var.server_name
        local time = ngx.localtime()
        if ua then
            line =
                realIp ..
                " [" ..
                    time ..
                        '] "' ..
                            method ..
                                " " .. servername .. url .. '" "' .. data .. '"  "' .. ua .. '" "' .. ruletag .. '"\n'
        else
            line =
                realIp ..
                " [" ..
                    time .. '] "' .. method .. " " .. servername .. url .. '" "' .. data .. '" - "' .. ruletag .. '"\n'
        end
        local filename = logpath .. "/" .. servername .. "_" .. ngx.today() .. "_sec.log"
        write(filename, line)
    end
end
------------------------------------规则读取函数-------------------------------------------------------------------
function read_rule(var)
    file = io.open(rulepath .. "/" .. var, "r")
    if file == nil then
        return
    end
    t = {}
    for line in file:lines() do
        table.insert(t, line)
    end
    file:close()
    return (t)
end

urlrules = read_rule("url")
argsrules = read_rule("args")
uarules = read_rule("user-agent")
wturlrules = read_rule("whiteurl")
postrules = read_rule("post")
ckrules = read_rule("cookie")

--返回 forbidden page && 403
function say_html()
    if Redirect then
        ngx.header.content_type = "text/html"
        ngx.status = ngx.HTTP_FORBIDDEN
        ngx.say(html)
        ngx.exit(ngx.status)
    end
end

-- check url
function whiteurl()
    if WhiteCheck then
        if wturlrules ~= nil then
            for _, rule in pairs(wturlrules) do
                if ngxmatch(ngx.var.uri, rule, "isjo") then
                    return true
                end
            end
        end
    end
    return false
end

-- 功能：正则匹配检查文件后缀名
function fileExtCheck(ext)
    -- items : { "php":true, "jsp" : true }
    -- TODO ? Set转换函数没意义？
    local items = Set(black_fileExt)
    ext = string.lower(ext)
    if ext then
        for rule in pairs(items) do
            if ngx.re.match(ext, rule, "isjo") then
                log("POST", ngx.var.request_uri, "-", "file attack with ext " .. ext)
                say_html()
            end
        end
    end
    return false
end

-- 将list中的value作为key， 设置为true {"php", "jsp"}
-- 返回值：{"val1": true, "val2": true, ...}
function Set(list)
    local set = {}
    for _, l in ipairs(list) do
        -- set["php"] =  true
        -- set["jsp"] =  true
        set[l] = true
    end
    return set
end

--  实现原理：将args的value用空格拼成一个串 ，匹配args的规则
function args()
    for _, rule in pairs(argsrules) do
        local args = ngx.req.get_uri_args()
        for key, val in pairs(args) do
            -- value is table
            if type(val) == "table" then
                -- tmp table saved
                local t = {}
                for k, v in pairs(val) do
                    -- continue value == true
                    if v == true then
                        v = ""
                    end
                    table.insert(t, v)
                end
                -- t = {"val1", "val2", "val3"}
                -- table.concat(t, " ")  ==>  data  = "val1 val2 val3"
                data = table.concat(t, " ")
            else
                -- data == "val1"
                data = val
            end
            -- syntax: captures, err = ngx.re.match(subject, regex, options?, ctx?, res_table?)
            -- options : "isjo"
            if data and type(data) ~= "boolean" and rule ~= "" and ngxmatch(unescape(data), rule, "isjo") then
                log("GET", ngx.var.request_uri, "-", rule, "args:", data)
                say_html()
                return true
            end
        end
    end
    return false
end

-- check url
function url()
    if UrlDeny then
        for _, rule in pairs(urlrules) do
            if rule ~= "" and ngxmatch(ngx.var.request_uri, rule, "isjo") then
                log("GET", ngx.var.request_uri, "-", rule)
                say_html()
                return true
            end
        end
    end
    return false
end

-- check UA
function ua()
    local ua = ngx.var.http_user_agent
    if ua ~= nil then
        for _, rule in pairs(uarules) do
            if rule ~= "" and ngxmatch(ua, rule, "isjo") then
                log("UA", ngx.var.request_uri, "-", rule)
                say_html()
                return true
            end
        end
    end
    return false
end

function body(data)
    for _, rule in pairs(postrules) do
        if rule ~= "" and data ~= "" and ngxmatch(unescape(data), rule, "isjo") then
            log("POST", ngx.var.request_uri, data, rule)
            say_html()
            return true
        end
    end
    return false
end

-- 函数原理： 使用整个cookie串匹配cookie规则
function cookie()
    local ck = ngx.var.http_cookie
    -- ck : key1=value1; key2=value2;
    if CookieCheck and ck then
        for _, rule in pairs(ckrules) do
            if rule ~= "" and ngxmatch(ck, rule, "isjo") then
                log("Cookie", ngx.var.request_uri, "-", rule)
                say_html()
                return true
            end
        end
    end
    return false
end

-- 将用户访问url的次数存储到共享内存中, key = remote_addr..uri, value =count
-- 如果共享内存不存在设置初始值，否则每次请求过来对value加1
-- 设置字典的超时时间dict::set(key,value, timeout)
function denycc()
    if CCDeny then
        local uri = ngx.var.uri
        -- get CCcount
        CCcount = tonumber(string.match(CCrate, "(.*)/"))
        -- get CCseconds
        CCseconds = tonumber(string.match(CCrate, "/(.*)"))

        -- token : 1.1.1.1/request_uri
        local token = getClientIp() .. uri

        -- 可以通过ngx.shared.DICT获取limit字典
        local limit = ngx.shared.limit

        -- 语法：value, flags = ngx.shared.DICT:get(key)
        local req, _ = limit:get(token)
        if req then
            if req > CCcount then
                ngx.exit(503)
                return true
            else
                limit:incr(token, 1)
            end
        else
            -- set (key, value, timeout)
            limit:set(token, 1, CCseconds)
        end
    end
    return false
end

function get_boundary()
    local header = get_headers()["content-type"]
    if not header then
        return nil
    end

    if type(header) == "table" then
        header = header[1]
    end

    local m = match(header, ';%s*boundary="([^"]+)"')
    if m then
        return m
    end

    return match(header, ';%s*boundary=([^",;]+)')
end

-- check whiteip
function whiteip()
    if next(ipWhitelist) ~= nil then
        for _, ip in pairs(ipWhitelist) do
            if getClientIp() == ip then
                return true
            end
        end
    end
    return false
end

function blockip()
    --lua中判断表是否为空的最安全的写法是用内置函数next
    if next(ipBlocklist) ~= nil then
        for _, ip in pairs(ipBlocklist) do
            if getClientIp() == ip then
                ngx.exit(403)
                return true
            end
        end
    end
    return false
end
