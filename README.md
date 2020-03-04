Inspired by the great work documenting AWS security practices in [asecure.cloud](https://asecure.cloud/whatsnew), this module is meant to define common Service Control Policies (SCP) to apply to accounts or Organizational Units (OU) in an AWS Organization. The following policies are supported

* Deny the root user from taking any action
* Deny the ability for an AWS account to leave an AWS organization
* Require S3 objects be encrypted
* Deny the ability to create IAM users and access keys in an AWS account
* Deny the ability to delete KMS keys
* Deny the ability to delete Route53 zones
* Deny all access to an AWS account
* Deny the ability to delete VPC flow logs

## Usage

```hcl
resource "aws_organizations_organizational_unit" "root" {
  name      = "root"
  parent_id = aws_organizations_organization.main.roots.0.id
}

resource "aws_organizations_organizational_unit" "id_destination" {
  name      = "id-destination"
  parent_id = aws_organizations_organizational_unit.root.id
}

resource "aws_organizations_organizational_unit" "prod" {
  name      = "prod"
  parent_id = aws_organizations_organizational_unit.id_destination.id
}

resource "aws_organizations_organizational_unit" "suspended" {
  depends_on = [aws_organizations_organization.main]

  name      = "suspended"
  parent_id = aws_organizations_organizational_unit.root.id
}

module "org_scps" {
  source  = "trussworks/org-scp/aws"
  version = "~> 1.2.0"

  # applies to all accounts
  # - don't allow all accounts to be able to leave the org
  # - don't allow access to the root user
  # - require s3 objects be encrypted
  deny_root_account_target_ids     = [aws_organizations_organizational_unit.root.id]
  deny_leaving_orgs_target_ids     = [aws_organizations_organizational_unit.root.id]
  require_s3_encryption_target_ids = [aws_organizations_organizational_unit.root.id]

  # applies to accounts that are not managing IAM users
  # - don't allow creating IAM users or access keys
  deny_creating_iam_users_target_ids = [aws_organizations_organizational_unit.id_destination.id]

  # applies to all prod accounts
  # - don't allow deleting KMS keys
  # - don't allow deleting Route53 zones
  deny_deleting_kms_keys_target_ids        = [aws_organizations_organizational_unit.prod.id]
  deny_deleting_route53_zones_target_ids   = [aws_organizations_organizational_unit.prod.id]
  deny_deleting_cloudwatch_logs_target_ids = [aws_organizations_organizational_unit.prod.id]

  # applies to all suspended accounts
  # - don't allow any access
  deny_all_access_target_ids = [aws_organizations_organizational_unit.suspended.id]
}
```

<!-- BEGINNING OF PRE-COMMIT-TERRAFORM DOCS HOOK -->
## Providers

| Name | Version |
|------|---------|
| aws | n/a |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:-----:|
| deny\_all\_access\_target\_ids | Target ids (AWS Account or Organizational Unit) to attach an SCP dening all access | `list(string)` | `[]` | no |
| deny\_creating\_iam\_users\_target\_ids | Target ids (AWS Account or Organizational Unit) to attach an SCP denying the ability to create IAM users or Access Keys | `list(string)` | `[]` | no |
| deny\_deleting\_cloudwatch\_logs\_target\_ids | Target ids (AWS Account or Organizational Unit) to delete VPC flow logs, log groups, or log streams | `list(string)` | `[]` | no |
| deny\_deleting\_kms\_keys\_target\_ids | Target ids (AWS Account or Organizational Unit) to attach an SCP denying deleting KMS keys | `list(string)` | `[]` | no |
| deny\_deleting\_route53\_zones\_target\_ids | Target ids (AWS Account or Organizational Unit) to attach an SCP denying deleting Route53 Hosted Zones | `list(string)` | `[]` | no |
| deny\_leaving\_orgs\_target\_ids | Target ids (AWS Account or Organizational Unit) to attach an SCP denying the ability to leave the AWS Organization | `list(string)` | `[]` | no |
| deny\_root\_account\_target\_ids | Target ids (AWS Account or Organizational Unit) to attach an SCP denying the root user from taking any action | `list(string)` | `[]` | no |
| require\_s3\_encryption\_target\_ids | Target ids (AWS Account or Organizational Unit) to attach an SCP requiring S3 encryption | `list(string)` | `[]` | no |

## Outputs

No output.

<!-- END OF PRE-COMMIT-TERRAFORM DOCS HOOK -->

## Developer Setup

Install dependencies (macOS)

```shell
brew install pre-commit terraform terraform-docs
pre-commit install --install-hooks
```
