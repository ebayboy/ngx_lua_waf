

black_fileExt={"php","jsp"}

-- 功能：正则匹配检查文件后缀名
function fileExtCheck(ext)
    -- items : { "php":true, "jsp" : true }
    local items = Set(black_fileExt)

    for k,v in ipairs(black_fileExt) do
        print("k1:", k1, "v1:", v)
    end

    for k,v in pairs(items) do
        print("k:", k, " v:", v)
    end

    --[[
    ext = string.lower(ext)
    if ext then
        for rule in pairs(items) do
            print("rule:", rule)
            if ngx.re.match(ext, rule, "isjo") then
                log("POST", ngx.var.request_uri, "-", "file attack with ext " .. ext)
                say_html()
            end
        end
    end
    ]]--

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

fileExtCheck("php")