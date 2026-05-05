param(
    [Parameter(Mandatory = $true)]
    [string]$BucketName,

    [string]$Region = "us-east-1",

    [Parameter(Mandatory = $true)]
    [string]$LoggingTargetBucket,

    [string]$LoggingTargetPrefix,

    [string]$TrailName
)

$configRoot = $PSScriptRoot
$lifecycleConfig = "file://$configRoot/lifecycle.json"
$encryptionConfig = "file://$configRoot/encryption.json"
$publicAccessBlockConfig = "file://$configRoot/public_access_block.json"
$loggingPolicyTemplatePath = Join-Path $configRoot "logging_bucket_policy.json"
$cloudTrailScript = Join-Path $configRoot "cloudtrail.ps1"

if (-not $LoggingTargetPrefix) {
    $LoggingTargetPrefix = "$BucketName/"
}

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
        Write-Host $SuccessMessage
        return
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

    Write-Host "Failed to $StepName for bucket $BucketName."
    if ($outputText) {
        Write-Host $outputText
    }
    exit 1
}

$loggingTemplatePath = Join-Path $configRoot "logging.json"
$loggingConfigContent = Get-Content -Path $loggingTemplatePath -Raw
$loggingConfigContent = $loggingConfigContent.Replace("__TARGET_BUCKET__", $LoggingTargetBucket)
$loggingConfigContent = $loggingConfigContent.Replace("__TARGET_PREFIX__", $LoggingTargetPrefix)
$loggingConfigPath = Join-Path $env:TEMP ("s3-logging-{0}.json" -f ([guid]::NewGuid().ToString("N")))
Set-Content -Path $loggingConfigPath -Value $loggingConfigContent -Encoding utf8
$loggingConfig = "file://$loggingConfigPath"
$loggingPolicyPath = Join-Path $env:TEMP ("s3-logging-policy-{0}.json" -f ([guid]::NewGuid().ToString("N")))

try {
    $accountId = Invoke-AwsValue -StepName "resolve AWS account ID" -KnownErrors @{
        "Unable to locate credentials|ExpiredToken|InvalidClientTokenId|AccessDenied" = "Unable to resolve the current AWS account ID. Check your AWS credentials before creating the bucket."
    } -Command {
        aws sts get-caller-identity --query Account --output text
    }

    Invoke-AwsStep -StepName "validate logging target bucket" -SuccessMessage "Logging target bucket $LoggingTargetBucket found." -KnownErrors @{
        "Not Found|NoSuchBucket|404" = "Logging target bucket $LoggingTargetBucket does not exist. Create it before enabling server access logging."
        "Forbidden|AccessDenied|403" = "Logging target bucket $LoggingTargetBucket is not accessible with the current AWS credentials."
    } -Command {
        aws s3api head-bucket --bucket $LoggingTargetBucket
    }

    $statementSid = "AllowS3ServerAccessLogsFor{0}" -f (($BucketName -replace "[^A-Za-z0-9]", "").Trim())
    $logObjectArn = if ($LoggingTargetPrefix) {
        "arn:aws:s3:::$LoggingTargetBucket/$LoggingTargetPrefix*"
    }
    else {
        "arn:aws:s3:::$LoggingTargetBucket/*"
    }

    $loggingPolicyContent = Get-Content -Path $loggingPolicyTemplatePath -Raw
    $loggingPolicyContent = $loggingPolicyContent.Replace("__STATEMENT_SID__", $statementSid)
    $loggingPolicyContent = $loggingPolicyContent.Replace("__LOG_OBJECT_RESOURCE__", $logObjectArn)
    $loggingPolicyContent = $loggingPolicyContent.Replace("__SOURCE_BUCKET_ARN__", "arn:aws:s3:::$BucketName")
    $loggingPolicyContent = $loggingPolicyContent.Replace("__ACCOUNT_ID__", $accountId)
    $desiredStatement = ($loggingPolicyContent | ConvertFrom-Json).Statement[0]

    $existingPolicyOutput = aws s3api get-bucket-policy --bucket $LoggingTargetBucket --query Policy --output text 2>&1
    $existingPolicyExitCode = $LASTEXITCODE
    $existingPolicyText = ($existingPolicyOutput | Out-String).Trim()

    if ($existingPolicyExitCode -eq 0 -and $existingPolicyText) {
        $loggingBucketPolicy = $existingPolicyText | ConvertFrom-Json
    }
    elseif ($existingPolicyText -match "NoSuchBucketPolicy") {
        $loggingBucketPolicy = [pscustomobject]@{
            Version = "2012-10-17"
            Statement = @()
        }
    }
    else {
        Write-Host "Failed to read existing policy for logging target bucket $LoggingTargetBucket."
        if ($existingPolicyText) {
            Write-Host $existingPolicyText
        }
        exit 1
    }

    if (-not $loggingBucketPolicy.PSObject.Properties['Statement']) {
        $loggingBucketPolicy | Add-Member -NotePropertyName Statement -NotePropertyValue @()
    }
    elseif ($null -eq $loggingBucketPolicy.Statement) {
        $loggingBucketPolicy.Statement = @()
    }

    $mergedStatements = @($loggingBucketPolicy.Statement | Where-Object { $_.Sid -ne $statementSid })
    $mergedStatements += $desiredStatement
    $loggingBucketPolicy.Statement = $mergedStatements

    Set-Content -Path $loggingPolicyPath -Value ($loggingBucketPolicy | ConvertTo-Json -Depth 10) -Encoding utf8

    Invoke-AwsStep -StepName "apply logging bucket policy" -SuccessMessage "Logging bucket policy updated for target bucket $LoggingTargetBucket." -KnownErrors @{
        "MalformedPolicy" = "Generated logging bucket policy is invalid."
        "AccessDenied" = "Access denied while updating the policy on logging target bucket $LoggingTargetBucket."
    } -Command {
        aws s3api put-bucket-policy --bucket $LoggingTargetBucket --policy "file://$loggingPolicyPath"
    }

    Invoke-AwsStep -StepName "create bucket" -SuccessMessage "Bucket $BucketName created successfully." -KnownErrors @{
        "BucketAlreadyOwnedByYou" = "Bucket $BucketName already exists in your account."
        "BucketAlreadyExists" = "Bucket $BucketName is already taken. Use a globally unique bucket name."
    } -Command {
        if ($Region -eq "us-east-1") {
            aws s3api create-bucket --bucket $BucketName --region $Region
        }
        else {
            aws s3api create-bucket `
                --bucket $BucketName `
                --region $Region `
                --create-bucket-configuration LocationConstraint=$Region
        }
    }

    Invoke-AwsStep -StepName "enable versioning" -SuccessMessage "Versioning enabled for bucket $BucketName." -Command {
        aws s3api put-bucket-versioning `
            --bucket $BucketName `
            --versioning-configuration Status=Enabled
    }

    Invoke-AwsStep -StepName "apply lifecycle configuration" -SuccessMessage "Lifecycle configuration applied to bucket $BucketName." -Command {
        aws s3api put-bucket-lifecycle-configuration `
            --bucket $BucketName `
            --lifecycle-configuration $lifecycleConfig
    }

    Invoke-AwsStep -StepName "apply bucket encryption" -SuccessMessage "Encryption enabled for bucket $BucketName." -Command {
        aws s3api put-bucket-encryption `
            --bucket $BucketName `
            --server-side-encryption-configuration $encryptionConfig
    }

    Invoke-AwsStep -StepName "apply public access block" -SuccessMessage "Public access block enabled for bucket $BucketName." -Command {
        aws s3api put-public-access-block `
            --bucket $BucketName `
            --public-access-block-configuration $publicAccessBlockConfig
    }

    Invoke-AwsStep -StepName "enable server access logging" -SuccessMessage "Server access logging enabled for bucket $BucketName using target bucket $LoggingTargetBucket." -KnownErrors @{
        "InvalidTargetBucketForLogging" = "Logging target bucket $LoggingTargetBucket is invalid for server access logging. Make sure it exists in the same region and grants log delivery permission."
    } -Command {
        aws s3api put-bucket-logging `
            --bucket $BucketName `
            --bucket-logging-status $loggingConfig
    }

    if ($TrailName) {
        & $cloudTrailScript -TrailName $TrailName -TrailBucketName $LoggingTargetBucket -DataBucketName $BucketName -Region $Region
        if ($LASTEXITCODE -ne 0) {
            Write-Host "Failed to configure CloudTrail trail $TrailName for bucket $BucketName."
            exit $LASTEXITCODE
        }
    }
}
finally {
    if (Test-Path $loggingConfigPath) {
        Remove-Item $loggingConfigPath -Force
    }

    if (Test-Path $loggingPolicyPath) {
        Remove-Item $loggingPolicyPath -Force
    }
}
    