param(
    [Parameter(Mandatory = $true)]
    [string]$BucketName,

    [string]$Region = "us-east-1",

    [string]$TrailName,

    [string]$LoggingTargetBucket
)

function Invoke-AwsStep {
    param(
        [string]$StepName,
        [string]$SuccessMessage,
        [scriptblock]$Command,
        [hashtable]$KnownErrors = @{}
    )

    $commandOutput = & $Command 2>&1
    $exitCode = $LASTEXITCODE

    if ($exitCode -eq 0) {
        if ($SuccessMessage) {
            Write-Host $SuccessMessage
        }
        return $commandOutput
    }

    $outputText = ($commandOutput | Out-String).Trim()

    foreach ($pattern in $KnownErrors.Keys) {
        if ($outputText -match $pattern) {
            Write-Host $KnownErrors[$pattern]
            exit 1
        }
    }

    Write-Host "Failed to $StepName for bucket $BucketName."
    if ($outputText) {
        Write-Host $outputText
    }
    exit 1
}

function Remove-S3Bucket {
    param(
        [string]$TargetBucketName
    )

    $headBucketOutput = aws s3api head-bucket --bucket $TargetBucketName 2>&1
    if ($LASTEXITCODE -ne 0) {
        $headBucketText = ($headBucketOutput | Out-String).Trim()
        if ($headBucketText -match "Not Found|NoSuchBucket|404") {
            Write-Host "Bucket $TargetBucketName does not exist or was already deleted."
            return
        }

        Write-Host "Failed to validate bucket $TargetBucketName before deletion."
        if ($headBucketText) {
            Write-Host $headBucketText
        }
        exit 1
    }

    $versionsJson = Invoke-AwsStep -StepName "list object versions" -Command {
        aws s3api list-object-versions --bucket $TargetBucketName --output json
    }

    $versionsResult = $versionsJson | ConvertFrom-Json
    $versionEntries = @()

    if ($versionsResult.Versions) {
        $versionEntries += $versionsResult.Versions | ForEach-Object {
            [pscustomobject]@{
                Key = $_.Key
                VersionId = $_.VersionId
                Label = "object version"
            }
        }
    }

    if ($versionsResult.DeleteMarkers) {
        $versionEntries += $versionsResult.DeleteMarkers | ForEach-Object {
            [pscustomobject]@{
                Key = $_.Key
                VersionId = $_.VersionId
                Label = "delete marker"
            }
        }
    }

    foreach ($entry in $versionEntries) {
        Invoke-AwsStep -StepName "delete $($entry.Label) $($entry.Key)" -Command {
            aws s3api delete-object --bucket $TargetBucketName --key $entry.Key --version-id $entry.VersionId --region $Region
        }
    }

    if ($versionEntries.Count -gt 0) {
        Write-Host "Removed $($versionEntries.Count) versioned item(s) from bucket $TargetBucketName."
    }
    else {
        Write-Host "Bucket $TargetBucketName is already empty."
    }

    Invoke-AwsStep -StepName "delete bucket" -SuccessMessage "Bucket $TargetBucketName deleted successfully." -KnownErrors @{
        "BucketNotEmpty" = "Bucket $TargetBucketName still has remaining object versions or delete markers."
    } -Command {
        aws s3api delete-bucket --bucket $TargetBucketName --region $Region
    }
}

if ($TrailName) {
    $trailOutput = aws cloudtrail get-trail --name $TrailName --region $Region 2>&1
    $trailExitCode = $LASTEXITCODE
    $trailText = ($trailOutput | Out-String).Trim()

    if ($trailExitCode -eq 0) {
        Invoke-AwsStep -StepName "stop CloudTrail logging" -SuccessMessage "CloudTrail logging stopped for trail $TrailName." -Command {
            aws cloudtrail stop-logging --name $TrailName --region $Region
        }

        Invoke-AwsStep -StepName "delete CloudTrail trail" -SuccessMessage "CloudTrail trail $TrailName deleted successfully." -Command {
            aws cloudtrail delete-trail --name $TrailName --region $Region
        }
    }
    elseif ($trailText -match "TrailNotFoundException|Cannot find trail") {
        Write-Host "CloudTrail trail $TrailName does not exist or was already deleted."
    }
    else {
        Write-Host "Failed to validate CloudTrail trail $TrailName before deletion."
        if ($trailText) {
            Write-Host $trailText
        }
        exit 1
    }
}

Remove-S3Bucket -TargetBucketName $BucketName

if ($LoggingTargetBucket -and $LoggingTargetBucket -ne $BucketName) {
    Remove-S3Bucket -TargetBucketName $LoggingTargetBucket
}

