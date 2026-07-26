Config = {}

-- Five minutes. Values below 30 seconds are rejected by server.lua.
Config.ScanInterval = 5 * 60 * 1000

-- Run once when this resource starts.
Config.ScanOnStart = true

-- Optional Discord webhook. Leave empty to report only in the server console.
Config.DiscordWebhook = ''
Config.DiscordUsername = 'X3roxDev Backdoor Fink'

-- New findings are sent once per server session. They are still shown in the
-- console on later scans when Config.ShowKnownFindings is true.
Config.ShowKnownFindings = true

-- A file must reach this score to be reported. Strong rules report immediately.
Config.MinimumScore = 6

-- Oversized generated/bundled files are skipped to keep scans responsive.
Config.MaxFileSize = 2 * 1024 * 1024

-- Resources that you intentionally do not want to inspect.
Config.IgnoredResources = {
    ['X3roxDev_backdoor_fink'] = true
}

-- Additional concrete files to try in every resource. Manifest files and all
-- declared scripts/files are always checked as well.
Config.CommonFiles = {
    'server.lua',
    'client.lua',
    'shared.lua',
    'config.lua',
    'index.js',
    'server.js'
}

-- Binary game assets are intentionally excluded.
Config.ScannableExtensions = {
    lua = true,
    js = true,
    ts = true,
    cs = true,
    json = true,
    cfg = true,
    ini = true,
    xml = true,
    html = true,
    htm = true,
    txt = true
}
