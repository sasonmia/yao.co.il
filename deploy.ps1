# Deploys Yuli to AWS Israel (Tel Aviv, il-central-1) from Windows PowerShell.
# Requires: AWS CLI v2 + AWS SAM CLI, and a logged-in profile (aws login --profile yuli).
# Optional: $env:DOMAIN="yao.co.il"; $env:CERT_ARN="arn:aws:acm:us-east-1:..."; $env:ALERT_EMAIL="you@example.com"
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
$Region = 'il-central-1'
$Stack  = 'yuli'
if (-not $env:AWS_PROFILE) { $env:AWS_PROFILE = 'yuli' }

function Run($cmd) { Invoke-Expression $cmd; if ($LASTEXITCODE -ne 0) { throw "Failed: $cmd" } }

Write-Host "Checking login..."
Run "aws sts get-caller-identity --region $Region"

if (-not (Test-Path .yuli-secret)) {
  $b = New-Object byte[] 32
  [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
  ($b | ForEach-Object { $_.ToString('x2') }) -join '' | Set-Content -NoNewline .yuli-secret
}
$secret = (Get-Content .yuli-secret -Raw).Trim()

Run "sam build --template-file infra/template.yaml"
Run ("sam deploy --template-file .aws-sam/build/template.yaml --stack-name $Stack --region $Region " +
     "--capabilities CAPABILITY_IAM --resolve-s3 --no-confirm-changeset --no-fail-on-empty-changeset " +
     "--parameter-overrides TokenSecret=$secret DomainName=$($env:DOMAIN) CertificateArn=$($env:CERT_ARN) AlertEmail=$($env:ALERT_EMAIL)")

function Out($k) { (aws cloudformation describe-stacks --stack-name $Stack --region $Region --query "Stacks[0].Outputs[?OutputKey=='$k'].OutputValue" --output text).Trim() }
$bucket = Out 'BucketName'; $dist = Out 'DistributionId'

Run "aws s3 cp index.html s3://$bucket/index.html --region $Region --content-type `"text/html; charset=utf-8`" --cache-control no-cache"
Run "aws cloudfront create-invalidation --distribution-id $dist --paths `"/*`" | Out-Null"

Write-Host ""
Write-Host "Site:  $(Out 'SiteUrl')"
Write-Host "CNAME for DNS -> $(Out 'CloudFrontDomain')"
