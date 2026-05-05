param(
    [Parameter(Mandatory = $true)]
    [string]$TrailBucketName,

    [Parameter(Mandatory = $true)]
    [string]$DataBucketName,

    [string]$Region = "us-east-1",

    [int]$HoursBack = 24,

    [int]$MaxTrailFiles = 20,

    [string]$EventName = "PutObject"
)

function Invoke-AwsValue {
    param(
        [string]$StepName,
        [scriptblock]$Command,
        [hashtable]$KnownErrors = @{}
    )

    $commandOutput = & $Command 2>&1
    $exitCode = $LASTEXITCODE
    $outputText = ($commandOutput | Out-String).Trim()

    if ($exitCode -eq 0) {
        return $outputText
    }

    foreach ($pattern in $KnownErrors.Keys) {
        if ($outputText -match $pattern) {
            Write-Host $KnownErrors[$pattern]
            exit 1
        }
    }

    Write-Host "Failed to $StepName."
    if ($outputText) {
        Write-Host $outputText
    }
    exit 1
}

$accountId = Invoke-AwsValue -StepName "resolve AWS account ID" -KnownErrors @{
    "Unable to locate credentials|ExpiredToken|InvalidClientTokenId|AccessDenied" = "Unable to resolve the current AWS account ID. Check your AWS credentials."
} -Command {
    aws sts get-caller-identity --query Account --output text
}

$prefix = "AWSLogs/$accountId/CloudTrail/$Region/"
$listJson = Invoke-AwsValue -StepName "list CloudTrail log objects" -KnownErrors @{
    "NoSuchBucket" = "CloudTrail log bucket $TrailBucketName does not exist."
    "AccessDenied" = "Access denied while listing CloudTrail log bucket $TrailBucketName."
} -Command {
    aws s3api list-objects-v2 --bucket $TrailBucketName --prefix $prefix --output json
}

$listResult = $listJson | ConvertFrom-Json

if (-not $listResult.Contents) {
    Write-Host "No CloudTrail log files found under s3://$TrailBucketName/$prefix"
    exit 0
}

$cutoffTime = (Get-Date).ToUniversalTime().AddHours(-$HoursBack)
$candidateObjects = @(
    $listResult.Contents |
        Where-Object { [datetime]$_.LastModified -ge $cutoffTime } |
        Sort-Object { [datetime]$_.LastModified } -Descending |
        Select-Object -First $MaxTrailFiles
)

if (-not $candidateObjects) {
    Write-Host "No CloudTrail log files found in the last $HoursBack hour(s) under s3://$TrailBucketName/$prefix"
    exit 0
}

$tempRoot = Join-Path $env:TEMP ("cloudtrail-check-{0}" -f ([guid]::NewGuid().ToString("N")))
New-Item -Path $tempRoot -ItemType Directory | Out-Null

try {
    $matchedEvents = @()

    foreach ($object in $candidateObjects) {
        $localFilePath = Join-Path $tempRoot ([System.IO.Path]::GetFileName($object.Key))

        $downloadOutput = aws s3 cp "s3://$TrailBucketName/$($object.Key)" $localFilePath 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Host "Failed to download CloudTrail log file s3://$TrailBucketName/$($object.Key)."
            Write-Host ($downloadOutput | Out-String).Trim()
            exit 1
        }

        $fileStream = [System.IO.File]::OpenRead($localFilePath)
        try {
            $gzipStream = New-Object System.IO.Compression.GzipStream($fileStream, [System.IO.Compression.CompressionMode]::Decompress)
            $reader = New-Object System.IO.StreamReader($gzipStream)
            $jsonText = $reader.ReadToEnd()
            $trailFile = $jsonText | ConvertFrom-Json
        }
        finally {
            if ($reader) {
                $reader.Dispose()
            }
            elseif ($gzipStream) {
                $gzipStream.Dispose()
            }
            $fileStream.Dispose()
        }

        foreach ($record in $trailFile.Records) {
            $resourceMatch = $record.resources | Where-Object {
                $_.type -eq "AWS::S3::Object" -and $_.ARN -like "arn:aws:s3:::$DataBucketName/*"
            }

            $bucketMatch = $record.requestParameters.bucketName -eq $DataBucketName

            if (
                $record.eventSource -eq "s3.amazonaws.com" -and
                $record.eventName -eq $EventName -and
                ($bucketMatch -or $resourceMatch)
            ) {
                $matchedEvents += [pscustomobject]@{
                    EventTime = $record.eventTime
                    EventName = $record.eventName
                    BucketName = $record.requestParameters.bucketName
                    Key = $record.requestParameters.key
                    User = $record.userIdentity.arn
                    SourceIpAddress = $record.sourceIPAddress
                    TrailFile = $object.Key
                }
            }
        }
    }

    if (-not $matchedEvents) {
        Write-Host "No $EventName events found for bucket $DataBucketName in the last $HoursBack hour(s)."
        Write-Host "CloudTrail delivery can take several minutes."
        exit 0
    }

    $matchedEvents |
        Sort-Object EventTime -Descending |
        Format-Table -AutoSize EventTime, EventName, BucketName, Key, User, SourceIpAddress
}
finally {
    if (Test-Path $tempRoot) {
        Remove-Item $tempRoot -Recurse -Force
    }
}