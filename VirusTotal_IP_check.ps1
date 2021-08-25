try {
	$swVTFileReportWR = Invoke-WebRequest -Method GET -Uri "https://www.virustotal.com/api/v3/ip_addresses/$args" -Headers @{"x-apikey"="$Env:zzVirusTotalAPI"}
}
catch {
	Write-Host $_.Exception.Message -ForegroundColor Red
	$_.Exception
	Write-Host "Maybe IP does not exit in VirusTotal"
	exit
}

$swVTFileReport   = $swVTFileReportWR.content | ConvertFrom-Json

Write-Host "+----------------------------------------------------------------------------------------------------"
Write-Host "| IP ADDRESS: $args"
Write-Host "+----------------------------------------------------------------------------------------------------"
Write-Host "Clean ........ " -NoNewLine
Write-Host $swVTFileReport.data.attributes.last_analysis_stats.harmless   -ForegroundColor Green
Write-Host "Suspicious ... " -NoNewLine
Write-Host $swVTFileReport.data.attributes.last_analysis_stats.suspicious -ForegroundColor Yellow
Write-Host "Malware ...... " -NoNewLine
Write-Host $swVTFileReport.data.attributes.last_analysis_stats.malicious  -ForegroundColor Red
Write-Host "Undetected ... " -NoNewLine
Write-Host $swVTFileReport.data.attributes.last_analysis_stats.undetected -ForegroundColor Yellow
Write-Host "Timeout ...... " -NoNewLine
Write-Host $swVTFileReport.data.attributes.last_analysis_stats.timeout    -ForegroundColor Yellow
Write-Host "----------------------------------------------------------------------------------------------------"
Write-Host ("ESET ......... Is " + $args + " " + $swVTFileReport.data.attributes.last_analysis_results.eset.method + "ed? " + $swVTFileReport.data.attributes.last_analysis_results.eset.category + "/" + $swVTFileReport.data.attributes.last_analysis_results.eset.result)
Write-Host "----------------------------------------------------------------------------------------------------"
