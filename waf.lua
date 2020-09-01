local content_length = tonumber(ngx.req.get_headers()["content-length"])
local method = ngx.req.get_method()
local ngxmatch = ngx.re.match

if whiteip() then
	-- check next
elseif blockip() then
	-- ngx.exit(403)
elseif denycc() then
	-- ngx.exit(503)
elseif ngx.var.http_Acunetix_Aspect then
	-- awvs扫描器
	ngx.exit(444)
elseif ngx.var.http_X_Scan_Memo then
	-- X-scan扫描器
	ngx.exit(444)
elseif whiteurl() then
	-- check next
elseif ua() then
	-- return forbidden page
elseif url() then
	-- return forbidden page
elseif args() then
	-- return forbidden page
elseif cookie() then
	-- return forbidden page
elseif PostCheck then
	-- check request body

	-- body 分为两种数据格式： 
	-- 1. multipart格式
	-- 2. key : value格式
	if method == "POST" then
		local boundary = get_boundary()
		if boundary then
			-- multipart 内容， 创建一个socket，接收文件内容存储到buffer中
			local len = string.len
			local sock, err = ngx.req.socket()
			if not sock then
				return
			end
			-- init_body ：
			-- Creates a new blank request body for the current request 
			-- and inializes the buffer for later request body data writing 
			-- via the ngx.req.append_body and ngx.req.finish_body APIs.
			ngx.req.init_body(128 * 1024)
			sock:settimeout(0)
			local content_length = nil
			content_length = tonumber(ngx.req.get_headers()["content-length"])
			local chunk_size = 4096
			if content_length < chunk_size then
				chunk_size = content_length
			end
			local size = 0
			while size < content_length do
				local data, err, partial = sock:receive(chunk_size)
				data = data or partial
				if not data then
					return
				end
				ngx.req.append_body(data)
				if body(data) then
					return true
				end
				size = size + len(data)
				local m = ngxmatch(data, [[Content-Disposition: form-data;(.+)filename="(.+)\\.(.*)"]], "ijo")
				if m then
					-- 文件传输
					-- 捕获组获取文件名
					fileExtCheck(m[3])
					filetranslate = true
				else
					-- 非文件传输
					if ngxmatch(data, "Content-Disposition:", "isjo") then
						filetranslate = false
					end
					if filetranslate == false then
						if body(data) then
							return true
						end
					end
				end
				local less = content_length - size
				if less < chunk_size then
					chunk_size = less
				end
			end
			ngx.req.finish_body()
		else
			-- just check request_body post_args
			ngx.req.read_body()

			-- get post_args
			local args = ngx.req.get_post_args()
			if not args then
				return
			end
			for key, val in pairs(args) do
				if type(val) == "table" then
					if type(val[1]) == "boolean" then
						-- don't check bool type value
						return
					end
					--  data :  "val1,val2, ..., valn"
					data = table.concat(val, ", ")
				else
					data = val
				end
				if data and type(data) ~= "boolean" and body(data) then
					-- TODO ？ 如果命中body， body函数内部返回403 forbidden page了， 不会继续执行body(key)了？ 
					body(key)
				end
			end
		end
	end
else
	return
end
