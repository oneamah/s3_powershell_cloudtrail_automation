param(
    [Parameter(Mandatory = $true)]
    [string]$TrailName,

    [Parameter(Mandatory = $true)]
    [string]$TrailBucketName,

    [Parameter(Mandatory = $true)]
    [string]$DataBucketName,

    [string]$Region = "us-east-1"
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

    Write-Host "Failed to $StepName."
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

$configRoot = $PSScriptRoot
$trailPolicyTemplatePath = Join-Path $configRoot "cloudtrail_bucket_policy.json"
$eventSelectorsTemplatePath = Join-Path $configRoot "cloudtrail_event_selectors.json"
$trailPolicyPath = Join-Path $env:TEMP ("cloudtrail-policy-{0}.json" -f ([guid]::NewGuid().ToString("N")))
$eventSelectorsPath = Join-Path $env:TEMP ("cloudtrail-selectors-{0}.json" -f ([guid]::NewGuid().ToString("N")))

try {
    Invoke-AwsStep -StepName "validate CloudTrail bucket" -SuccessMessage "CloudTrail log bucket $TrailBucketName found." -KnownErrors @{
        "Not Found|NoSuchBucket|404" = "CloudTrail log bucket $TrailBucketName does not exist. Create it before enabling CloudTrail."
        "Forbidden|AccessDenied|403" = "CloudTrail log bucket $TrailBucketName is not accessible with the current AWS credentials."
    } -Command {
        aws s3api head-bucket --bucket $TrailBucketName
    }

    Invoke-AwsStep -StepName "validate data bucket" -SuccessMessage "Data bucket $DataBucketName found." -KnownErrors @{
        "Not Found|NoSuchBucket|404" = "Data bucket $DataBucketName does not exist."
        "Forbidden|AccessDenied|403" = "Data bucket $DataBucketName is not accessible with the current AWS credentials."
    } -Command {
        aws s3api head-bucket --bucket $DataBucketName
    }

    $trailPolicyContent = Get-Content -Path $trailPolicyTemplatePath -Raw
    $trailPolicyContent = $trailPolicyContent.Replace("__TRAIL_BUCKET_NAME__", $TrailBucketName)
    $trailPolicyContent = $trailPolicyContent.Replace("__ACCOUNT_ID__", $accountId)
    $trailPolicyContent = $trailPolicyContent.Replace("__TRAIL_NAME__", $TrailName)
    Set-Content -Path $trailPolicyPath -Value $trailPolicyContent -Encoding utf8

    Invoke-AwsStep -StepName "apply CloudTrail bucket policy" -SuccessMessage "CloudTrail bucket policy updated for $TrailBucketName." -KnownErrors @{
        "MalformedPolicy" = "Generated CloudTrail bucket policy is invalid."
        "AccessDenied" = "Access denied while updating the policy on CloudTrail bucket $TrailBucketName."
    } -Command {
        aws s3api put-bucket-policy --bucket $TrailBucketName --policy "file://$trailPolicyPath"
    }

    $trailExistsOutput = aws cloudtrail get-trail --name $TrailName 2>&1
    $trailExists = $LASTEXITCODE -eq 0

    if (-not $trailExists) {
        Invoke-AwsStep -StepName "create CloudTrail trail" -SuccessMessage "CloudTrail trail $TrailName created." -KnownErrors @{
            "TrailAlreadyExistsException" = "CloudTrail trail $TrailName already exists."
        } -Command {
            aws cloudtrail create-trail --name $TrailName --s3-bucket-name $TrailBucketName --is-multi-region-trail --region $Region
        }
    }
    else {
        Invoke-AwsStep -StepName "update CloudTrail trail" -SuccessMessage "CloudTrail trail $TrailName updated." -Command {
            aws cloudtrail update-trail --name $TrailName --s3-bucket-name $TrailBucketName --is-multi-region-trail --region $Region
        }
    }

    $eventSelectorsContent = Get-Content -Path $eventSelectorsTemplatePath -Raw
    $eventSelectorsContent = $eventSelectorsContent.Replace("__DATA_BUCKET_ARN__", "arn:aws:s3:::$DataBucketName/")
    Set-Content -Path $eventSelectorsPath -Value $eventSelectorsContent -Encoding utf8

    Invoke-AwsStep -StepName "set CloudTrail event selectors" -SuccessMessage "CloudTrail data event selectors applied for bucket $DataBucketName." -Command {
        aws cloudtrail put-event-selectors --trail-name $TrailName --advanced-event-selectors "file://$eventSelectorsPath" --region $Region
    }

    Invoke-AwsStep -StepName "start CloudTrail logging" -SuccessMessage "CloudTrail logging started for trail $TrailName." -Command {
        aws cloudtrail start-logging --name $TrailName --region $Region
    }

    Write-Host "CloudTrail is configured to capture S3 object-level events for bucket $DataBucketName."
    Write-Host "CloudTrail event history and lookup-events do not show S3 data events."
    Write-Host "Check delivered trail logs with: .\s3\cloudtrail-check.ps1 -TrailBucketName $TrailBucketName -DataBucketName $DataBucketName -Region $Region"
}
finally {
    if (Test-Path $trailPolicyPath) {
        Remove-Item $trailPolicyPath -Force
    }

    if (Test-Path $eventSelectorsPath) {
        Remove-Item $eventSelectorsPath -Force
    }
}