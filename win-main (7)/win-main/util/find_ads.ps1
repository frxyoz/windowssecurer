Write-Output "Finding files with alternate data streams, may take a while"
get-ChildItem -recurse | ForEach-Object { get-item $_.FullName -stream * } | Where-Object stream -ne ':$Data' | Select-Object filename,stream,@{'name'='identifier';"e"={"$($_.filename):$($_.stream)"}} > ads_files.txt

# https://jpsoft.com/forums/threads/finding-files-with-alternate-data-streams.9741/