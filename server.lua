local scanRunning = false
local reportedFindings = {}

local ARTWORK = [[
============================================================
 Backdoor Finder
 FiveM resource scanner for suspicious server/client scripts
============================================================
]]

-- These are Lua patterns, not plain strings. Scores are combined per file.
local RULES = {
    { id = 'loadstring', label = 'Dynamic code execution (loadstring)', pattern = 'loadstring%s*%(', score = 10, strong = true },
    { id = 'assert_load', label = 'Dynamic code execution (assert/load)', pattern = 'assert%s*%(%s*load%s*%(', score = 10, strong = true },
    { id = 'http', label = 'HTTP request capability', pattern = 'performhttprequest%s*%(', score = 2 },
    { id = 'dynamic_load', label = 'Dynamic load call', pattern = '%f[%a]load%s*%(', score = 5 },
    { id = 'eval', label = 'Dynamic JavaScript evaluation', pattern = '%f[%a]eval%s*%(', score = 6 },
    { id = 'function_ctor', label = 'Dynamic JavaScript Function constructor', pattern = 'new%s+function%s*%(', score = 5 },
    { id = 'fetch', label = 'Remote fetch capability', pattern = '%f[%a]fetch%s*%(', score = 2 },
    { id = 'os_execute', label = 'Operating-system command execution', pattern = 'os%.execute%s*%(', score = 10, strong = true },
    { id = 'io_popen', label = 'Operating-system pipe execution', pattern = 'io%.popen%s*%(', score = 10, strong = true },
    { id = 'powershell', label = 'PowerShell command reference', pattern = 'powershell', score = 8 },
    { id = 'cmd_exec', label = 'Windows command-shell reference', pattern = 'cmd%.exe', score = 8 },
    { id = 'paste_service', label = 'Paste/remote payload host', pattern = 'pastebin%.com', score = 4 },
    { id = 'raw_github', label = 'Raw remote source host', pattern = 'raw%.githubusercontent%.com', score = 3 },
    { id = 'discord_cdn', label = 'Discord CDN reference', pattern = 'cdn%.discordapp%.com', score = 2 },
    { id = 'global_obfuscation', label = 'Obfuscated global-table access', pattern = '_g%s*%[', score = 3 },
    { id = 'hex_escape_blob', label = 'Large escaped byte sequence', pattern = '\\x%x%x\\x%x%x\\x%x%x\\x%x%x\\x%x%x\\x%x%x', score = 5 },
    { id = 'char_blob', label = 'Encoded character construction', pattern = 'string%.char%s*%([^%)]*,[^%)]*,[^%)]*,[^%)]*,[^%)]*,', score = 4 },
    { id = 'base64_blob', label = 'Large Base64-like payload', pattern = '[%w%+/%=][%w%+/%=][%w%+/%=][%w%+/%=][%w%+/%=][%w%+/%=][%w%+/%=][%w%+/%=][%w%+/%=][%w%+/%=][%w%+/%=][%w%+/%=][%w%+/%=][%w%+/%=][%w%+/%=][%w%+/%=][%w%+/%=][%w%+/%=][%w%+/%=][%w%+/%=][%w%+/%=][%w%+/%=][%w%+/%=][%w%+/%=][%w%+/%=][%w%+/%=][%w%+/%=][%w%+/%=][%w%+/%=][%w%+/%=][%w%+/%=][%w%+/%=][%w%+/%=][%w%+/%=][%w%+/%=][%w%+/%=][%w%+/%=][%w%+/%=][%w%+/%=][%w%+/%=]', score = 3 }
}

local METADATA_KEYS = {
    'server_script',
    'client_script',
    'shared_script',
    'file'
}

local function log(message, color)
    print(('%s[X3roxDev_backdoor_fink]^7 %s'):format(color or '^5', message))
end

local function jsonEscape(value)
    return tostring(value)
        :gsub('\\', '\\\\')
        :gsub('"', '\\"')
        :gsub('\n', '\\n')
        :gsub('\r', '\\r')
        :gsub('\t', '\\t')
end

local function sendDiscord(findings, scannedResources, scannedFiles)
    if not Config.DiscordWebhook or Config.DiscordWebhook == '' or #findings == 0 then
        return
    end

    local lines = {}
    local limit = math.min(#findings, 20)
    for index = 1, limit do
        local finding = findings[index]
        lines[#lines + 1] = ('**%s/%s:%d** - `%s` (score %d)'):format(
            finding.resource,
            finding.file,
            finding.line,
            finding.rule,
            finding.score
        )
    end
    if #findings > limit then
        lines[#lines + 1] = ('...and %d more finding(s). See the server console.'):format(#findings - limit)
    end

    local description = table.concat(lines, '\n'):sub(1, 3900)
    local payload = ('{"username":"%s","embeds":[{"title":"Possible FiveM backdoor detected","description":"%s","color":15158332,"footer":{"text":"Scanned %d resources / %d files"}}]}'):format(
        jsonEscape(Config.DiscordUsername or 'X3roxDev Backdoor Fink'),
        jsonEscape(description),
        scannedResources,
        scannedFiles
    )

    PerformHttpRequest(Config.DiscordWebhook, function(statusCode)
        local status = tonumber(statusCode) or 0
        if status < 200 or status >= 300 then
            log(('Discord webhook returned HTTP %s.'):format(statusCode or 'unknown'), '^1')
        end
    end, 'POST', payload, { ['Content-Type'] = 'application/json' })
end

local function lineNumberAt(content, position)
    local _, newlineCount = content:sub(1, position):gsub('\n', '')
    return newlineCount + 1
end

local function inspectFile(resourceName, fileName, content)
    local lowered = content:lower()
    local matches = {}
    local score = 0
    local strong = false

    for _, rule in ipairs(RULES) do
        local position = lowered:find(rule.pattern)
        if position then
            score = score + rule.score
            strong = strong or rule.strong == true
            matches[#matches + 1] = {
                id = rule.id,
                label = rule.label,
                line = lineNumberAt(lowered, position)
            }
        end
    end

    if not strong and score < (tonumber(Config.MinimumScore) or 6) then
        return {}
    end

    local findings = {}
    for _, match in ipairs(matches) do
        findings[#findings + 1] = {
            resource = resourceName,
            file = fileName,
            line = match.line,
            rule = match.label,
            ruleId = match.id,
            score = score
        }
    end
    return findings
end

local function isConcreteSafePath(path)
    if not path or path == '' then return false end
    if path:sub(1, 1) == '@' then return false end
    if path:find('..', 1, true) then return false end
    if path:find('[%*%?]') then return false end
    if path:find('^https?://') then return false end
    return true
end

local function isScannableFile(path)
    if path == 'fxmanifest.lua' or path == '__resource.lua' then return true end
    local extension = path:lower():match('%.([%w]+)$')
    return extension ~= nil and (Config.ScannableExtensions or {})[extension] == true
end

local function collectFiles(resourceName)
    local files = {
        ['fxmanifest.lua'] = true,
        ['__resource.lua'] = true
    }

    for _, key in ipairs(METADATA_KEYS) do
        local count = GetNumResourceMetadata(resourceName, key) or 0
        for index = 0, count - 1 do
            local path = GetResourceMetadata(resourceName, key, index)
            if isConcreteSafePath(path) and isScannableFile(path) then
                files[path:gsub('\\', '/')] = true
            end
        end
    end

    for _, path in ipairs(Config.CommonFiles or {}) do
        if isConcreteSafePath(path) and isScannableFile(path) then
            files[path:gsub('\\', '/')] = true
        end
    end

    return files
end

local function runScan(trigger)
    if scanRunning then
        log('A scan is already running; skipping this request.', '^3')
        return
    end
    scanRunning = true

    local startedAt = GetGameTimer()
    local scannedResources = 0
    local scannedFiles = 0
    local allFindings = {}
    local newFindings = {}

    log(('Starting %s scan...'):format(trigger or 'scheduled'), '^5')

    local resourceCount = GetNumResources()
    for resourceIndex = 0, resourceCount - 1 do
        local resourceName = GetResourceByFindIndex(resourceIndex)
        if resourceName and not (Config.IgnoredResources or {})[resourceName] then
            scannedResources = scannedResources + 1
            for fileName in pairs(collectFiles(resourceName)) do
                local content = LoadResourceFile(resourceName, fileName)
                if content and #content <= (tonumber(Config.MaxFileSize) or 2097152) then
                    scannedFiles = scannedFiles + 1
                    local findings = inspectFile(resourceName, fileName, content)
                    for _, finding in ipairs(findings) do
                        local key = ('%s|%s|%s|%d'):format(finding.resource, finding.file, finding.ruleId, finding.line)
                        finding.isNew = not reportedFindings[key]
                        allFindings[#allFindings + 1] = finding
                        if finding.isNew then
                            reportedFindings[key] = true
                            newFindings[#newFindings + 1] = finding
                        end
                    end
                end
            end
        end

        -- Yield periodically so a large server does not stall the main thread.
        if resourceIndex % 10 == 0 then Wait(0) end
    end

    local elapsed = GetGameTimer() - startedAt
    if #allFindings == 0 then
        log(('Scan complete: %d resources, %d files, no suspicious files (%d ms).'):format(scannedResources, scannedFiles, elapsed), '^2')
    else
        log(('WARNING: %d suspicious indicator(s) in %d resources / %d files (%d new, %d ms).'):format(#allFindings, scannedResources, scannedFiles, #newFindings, elapsed), '^1')
        for _, finding in ipairs(allFindings) do
            if finding.isNew or Config.ShowKnownFindings then
                log(('%s%s/%s:%d - %s [file score: %d]'):format(
                    finding.isNew and '[NEW] ' or '[KNOWN] ',
                    finding.resource,
                    finding.file,
                    finding.line,
                    finding.rule,
                    finding.score
                ), finding.isNew and '^1' or '^3')
            end
        end
    end

    sendDiscord(newFindings, scannedResources, scannedFiles)
    scanRunning = false
end

print(ARTWORK)
log('Scanner loaded. Use "X3roxDev_scan" for a manual scan.', '^2')

RegisterCommand('X3roxDev_scan', function(source)
    if source ~= 0 then
        log(('Player %d tried to run the console-only scan command.'):format(source), '^3')
        return
    end
    CreateThread(function() runScan('manual') end)
end, true)

CreateThread(function()
    if Config.ScanOnStart then
        Wait(2000)
        runScan('startup')
    end

    local interval = math.max(tonumber(Config.ScanInterval) or 300000, 30000)
    while true do
        Wait(interval)
        runScan('scheduled')
    end
end)
