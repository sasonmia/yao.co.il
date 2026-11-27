#!/usr/bin/env bash
# Deploys Yuli to AWS Israel (Tel Aviv): API + DynamoDB + S3 + CloudFront.
# Requirements: AWS CLI v2 and AWS SAM CLI, with credentials for your AWS account.
# Optional env vars: DOMAIN=yao.co.il  CERT_ARN=<ACM cert in us-east-1>  ALERT_EMAIL=you@example.com
set -euo pipefail
cd "$(dirname "$0")"
REGION=il-central-1
STACK=yuli

# Token-signing secret: created once, kept locally (never commit it).
[ -f .yuli-admin-key ] || { openssl rand -hex 24 > .yuli-admin-key; chmod 600 .yuli-admin-key; }
[ -f .yuli-secret ] || { openssl rand -hex 32 > .yuli-secret; chmod 600 .yuli-secret; }

sam build --template-file infra/template.yaml
sam deploy --template-file .aws-sam/build/template.yaml \
  --stack-name "$STACK" --region "$REGION" \
  --capabilities CAPABILITY_IAM --resolve-s3 --no-confirm-changeset --no-fail-on-empty-changeset \
  --parameter-overrides \
    "TokenSecret=$(cat .yuli-secret)" "AdminKey=$(cat .yuli-admin-key)" \
    "DomainName=${DOMAIN:-}" "CertificateArn=${CERT_ARN:-}" "AlertEmail=${ALERT_EMAIL:-}"

out() { aws cloudformation describe-stacks --stack-name "$STACK" --region "$REGION" \
  --query "Stacks[0].Outputs[?OutputKey=='$1'].OutputValue" --output text; }
BUCKET=$(out BucketName); DIST=$(out DistributionId)

aws s3 cp index.html "s3://$BUCKET/index.html" --region "$REGION" \
  --content-type "text/html; charset=utf-8" --cache-control "no-cache"
aws s3 cp admin.html "s3://$BUCKET/admin.html" --region "$REGION" \
  --content-type "text/html; charset=utf-8" --cache-control "no-cache"
aws cloudfront create-invalidation --distribution-id "$DIST" --paths "/*" >/dev/null

echo
echo "Site:       $(out SiteUrl)"
echo "Admin page: $(out SiteUrl)/admin.html   (admin key is in .yuli-admin-key)"
echo "NOTE: open the SES verification email sent to your Gmail and click the link (needed once, to send approval emails)."
echo "CNAME for DNS -> $(out CloudFrontDomain)"
