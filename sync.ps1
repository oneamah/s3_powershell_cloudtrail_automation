param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("create", "upload", "cloudtrail", "destroy", "download", "check", "full")]
    [string]$Action,

    [Parameter(Mandatory = $true)]
    [string]$BucketName,

    [string]$Region = "us-east-1",

    [string]$FilePath,

    [string]$DestinationPath,

    [string]$Key,

    [string]$LoggingTargetBucket,

    [string]$LoggingTargetPrefix,

    [string]$TrailName,

    [string]$HoursBack = "24"
)

$scriptRoot = $PSScriptRoot
$createScript = Join-Path $scriptRoot "s3\create.ps1"
$putScript = Join-Path $scriptRoot "s3\put.ps1"
$getScript = Join-Path $scriptRoot "s3\get.ps1"
$destroyScript = Join-Path $scriptRoot "s3\destroy.ps1"
$cloudTrailScript = Join-Path $scriptRoot "s3\cloudtrail.ps1"
$cloudTrailCheckScript = Join-Path $scriptRoot "s3\cloudtrail-check.ps1"

function Invoke-S3Script {
    param(
        [string]$StepName,
        [scriptblock]$Command
    )

    & $Command
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Step '$StepName' failed."
        exit $LASTEXITCODE
    }
}

switch ($Action) {
    "create" {
        if (-not $LoggingTargetBucket) {
            Write-Host "LoggingTargetBucket is required for the create action."
            exit 1
        }

        Invoke-S3Script -StepName "create bucket" -Command {
            & $createScript -BucketName $BucketName -Region $Region -LoggingTargetBucket $LoggingTargetBucket -LoggingTargetPrefix $LoggingTargetPrefix -TrailName $TrailName
        }
    }
    "upload" {
        if (-not $FilePath) {
            Write-Host "FilePath is required for the upload action."
            exit 1
        }

        Invoke-S3Script -StepName "upload object" -Command {
            & $putScript -BucketName $BucketName -FilePath $FilePath -Key $Key -Region $Region
        }
    }
    "cloudtrail" {
        if (-not $TrailName) {
            Write-Host "TrailName is required for the cloudtrail action."
            exit 1
        }

        if (-not $LoggingTargetBucket) {
            Write-Host "LoggingTargetBucket is required for the cloudtrail action."
            exit 1
        }

        Invoke-S3Script -StepName "configure CloudTrail" -Command {
            & $cloudTrailScript -TrailName $TrailName -TrailBucketName $LoggingTargetBucket -DataBucketName $BucketName -Region $Region
        }
    }
    "destroy" {
        Invoke-S3Script -StepName "destroy bucket" -Command {
            & $destroyScript -BucketName $BucketName -Region $Region -TrailName $TrailName -LoggingTargetBucket $LoggingTargetBucket
        }
    }
    "download" {
        if (-not $DestinationPath) {
            Write-Host "DestinationPath is required for the download action."
            exit 1
        }

        Invoke-S3Script -StepName "download object" -Command {
            & $getScript -BucketName $BucketName -DestinationPath $DestinationPath -Key $Key -Region $Region
        }
    }
    "check" {
        if (-not $LoggingTargetBucket) {
            Write-Host "LoggingTargetBucket is required for the check action."
            exit 1
        }

        Invoke-S3Script -StepName "check CloudTrail events" -Command {
            & $cloudTrailCheckScript -TrailBucketName $LoggingTargetBucket -DataBucketName $BucketName -Region $Region -HoursBack $HoursBack
        }
    }
    "full" {
        if (-not $LoggingTargetBucket) {
            Write-Host "LoggingTargetBucket is required for the full action."
            exit 1
        }

        if (-not $TrailName) {
            Write-Host "TrailName is required for the full action."
            exit 1
        }

        if (-not $FilePath) {
            Write-Host "FilePath is required for the full action."
            exit 1
        }

        Invoke-S3Script -StepName "create bucket" -Command {
            & $createScript -BucketName $BucketName -Region $Region -LoggingTargetBucket $LoggingTargetBucket -LoggingTargetPrefix $LoggingTargetPrefix -TrailName $TrailName
        }

        Invoke-S3Script -StepName "upload object" -Command {
            & $putScript -BucketName $BucketName -FilePath $FilePath -Key $Key -Region $Region
        }
    }
}