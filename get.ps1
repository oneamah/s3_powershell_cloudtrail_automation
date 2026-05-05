param(
    [Parameter(Mandatory = $true)]
    [string]$BucketName,

    [Parameter(Mandatory = $true)]
    [string]$DestinationPath,

    [string]$Key,

    [string]$Region = "us-east-1"
)

if (-not $Key) {
    Write-Host "Key is required to download an object."
    exit 1
}

$destinationDirectory = Split-Path -Path $DestinationPath -Parent
if ($destinationDirectory -and -not (Test-Path -Path $destinationDirectory)) {
    New-Item -Path $destinationDirectory -ItemType Directory | Out-Null
}

$resolvedDestinationPath = [System.IO.Path]::GetFullPath($DestinationPath)
$getOutput = aws s3 cp "s3://$BucketName/$Key" $resolvedDestinationPath --region $Region 2>&1
$exitCode = $LASTEXITCODE

if ($exitCode -eq 0) {
    Write-Host "Object s3://$BucketName/$Key downloaded to $resolvedDestinationPath successfully."
    Write-Host "If CloudTrail data events are enabled for this bucket, check recent GetObject records with: .\s3\cloudtrail-check.ps1 -TrailBucketName <cloudtrail-log-bucket> -DataBucketName $BucketName -Region $Region -EventName GetObject"
}
elseif ($getOutput -match "NoSuchBucket") {
    Write-Host "Bucket $BucketName does not exist."
    exit 1
}
elseif ($getOutput -match "NoSuchKey|404") {
    Write-Host "Object key $Key does not exist in bucket $BucketName."
    exit 1
}
elseif ($getOutput -match "AccessDenied") {
    Write-Host "Access denied while downloading from bucket $BucketName."
    exit 1
}
else {
    Write-Host "Failed to download s3://$BucketName/$Key to $resolvedDestinationPath."
    if ($getOutput) {
        Write-Host ($getOutput | Out-String).Trim()
    }
    exit 1
}