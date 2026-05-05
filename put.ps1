param(
	[Parameter(Mandatory = $true)]
	[string]$BucketName,

	[Parameter(Mandatory = $true)]
	[string]$FilePath,

	[string]$Key,

	[string]$Region = "us-east-1"
)

if (-not (Test-Path -Path $FilePath -PathType Leaf)) {
	Write-Host "File $FilePath does not exist."
	exit 1
}

$resolvedFilePath = (Resolve-Path -Path $FilePath).Path

if (-not $Key) {
	$Key = Split-Path -Path $resolvedFilePath -Leaf
}

$putOutput = aws s3 cp $resolvedFilePath "s3://$BucketName/$Key" --region $Region 2>&1
$exitCode = $LASTEXITCODE

if ($exitCode -eq 0) {
	Write-Host "File $resolvedFilePath uploaded to s3://$BucketName/$Key successfully."
	Write-Host "If CloudTrail data events are enabled for this bucket, check recent PutObject records with: .\s3\cloudtrail-check.ps1 -TrailBucketName <cloudtrail-log-bucket> -DataBucketName $BucketName -Region $Region"
}
elseif ($putOutput -match "NoSuchBucket") {
	Write-Host "Bucket $BucketName does not exist."
	exit 1
}
elseif ($putOutput -match "AccessDenied") {
	Write-Host "Access denied while uploading to bucket $BucketName."
	exit 1
}
else {
	Write-Host "Failed to upload file $resolvedFilePath to s3://$BucketName/$Key."
	if ($putOutput) {
		Write-Host ($putOutput | Out-String).Trim()
	}
	exit 1
}
