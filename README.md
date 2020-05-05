# AWS Organization SCP Terraform Module

Inspired by the great work documenting AWS security practices in [asecure.cloud](https://asecure.cloud/whatsnew), this module is meant to define common Service Control Policies (SCP) to apply to accounts or Organizational Units (OU) in an AWS Organization. The following policies are supported

## Organizations

* Deny the ability for an AWS account to leave an AWS organization
* Deny all access to an AWS account

## IAM

* Deny the root user from taking any action
* Deny the ability to create IAM users and access keys in an AWS account
* Protect sensitive IAM roles from modification or deletion

## S3

* Protect sensitive S3 buckets from deletion

## KMS

* Deny the ability to delete KMS keys

## Route53

* Deny the ability to delete Route53 zones

## CloudWatch Logs

* Deny the ability to delete CloudWatch Logs

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
  version = "~> 1.4.0"

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
  # - don't allow deleting CloudWatch logs
  # - protect terraform statefile bucket
  # - protect OrganizationAccountAccessRole
  deny_deleting_kms_keys_target_ids        = [aws_organizations_organizational_unit.prod.id]
  deny_deleting_route53_zones_target_ids   = [aws_organizations_organizational_unit.prod.id]
  deny_deleting_cloudwatch_logs_target_ids = [aws_organizations_organizational_unit.prod.id]
  protect_s3_bucket_target_ids             = [aws_organizations_organizational_unit.prod.id]
  protect_iam_role_target_ids              = [aws_organizations_organizational_unit.prod.id]

  protect_s3_bucket_resources = [
    "arn:aws:s3:::prod-terraform-state-us-west-2",
    "arn:aws:s3:::prod-terraform-state-us-west-2/*"
  ]
  protect_iam_role_resources = [
    "arn:aws:iam::*:role/OrganizationAccountAccessRole"
  ]

  # applies to all suspended accounts
  # - don't allow any access
  deny_all_access_target_ids = [aws_organizations_organizational_unit.suspended.id]
}
```

<!-- BEGINNING OF PRE-COMMIT-TERRAFORM DOCS HOOK -->
## Requirements

| Name | Version |
|------|---------|
| terraform | >= 0.12 |

## Providers

| Name | Version |
|------|---------|
| aws | n/a |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| allowed\_regions | AWS Regions allowed for use (for use with the restrict regions SCP) | `list(string)` | <pre>[<br>  ""<br>]</pre> | no |
| deny\_all\_access\_target\_ids | Target ids (AWS Account or Organizational Unit) to attach an SCP dening all access | `list(string)` | `[]` | no |
| deny\_creating\_iam\_users\_target\_ids | Target ids (AWS Account or Organizational Unit) to attach an SCP denying the ability to create IAM users or Access Keys | `list(string)` | `[]` | no |
| deny\_deleting\_cloudwatch\_logs\_target\_ids | Target ids (AWS Account or Organizational Unit) to attach an SCP denying deletion of CloudWatch, flowlogs,  log groups, or log streams | `list(string)` | `[]` | no |
| deny\_deleting\_kms\_keys\_target\_ids | Target ids (AWS Account or Organizational Unit) to attach an SCP denying deleting KMS keys | `list(string)` | `[]` | no |
| deny\_deleting\_route53\_zones\_target\_ids | Target ids (AWS Account or Organizational Unit) to attach an SCP denying deleting Route53 Hosted Zones | `list(string)` | `[]` | no |
| deny\_leaving\_orgs\_target\_ids | Target ids (AWS Account or Organizational Unit) to attach an SCP denying the ability to leave the AWS Organization | `list(string)` | `[]` | no |
| deny\_root\_account\_target\_ids | Target ids (AWS Account or Organizational Unit) to attach an SCP denying the root user from taking any action | `list(string)` | `[]` | no |
| protect\_iam\_role\_resources | IAM role resource ARNs to protect from modification and deletion | `list(string)` | <pre>[<br>  ""<br>]</pre> | no |
| protect\_iam\_role\_target\_ids | Target ids (AWS Account or Organizational Unit) to attach an SCP protecting IAM roles | `list(string)` | `[]` | no |
| protect\_s3\_bucket\_resources | S3 bucket resource ARNs to protect from bucket and object deletion | `list(string)` | <pre>[<br>  ""<br>]</pre> | no |
| protect\_s3\_bucket\_target\_ids | Target ids (AWS Account or Organizational Unit) to attach an SCP protecting S3 buckets and objects | `list(string)` | `[]` | no |
| require\_s3\_encryption\_target\_ids | Target ids (AWS Account or Organizational Unit) to attach an SCP requiring S3 encryption | `list(string)` | `[]` | no |
| restrict\_regions\_target\_ids | Target ids (AWS Account or Organizational Unit) to attach an SCP restricting regions. | `list(string)` | `[]` | no |

## Outputs

No output.

<!-- END OF PRE-COMMIT-TERRAFORM DOCS HOOK -->

## Developer Setup

Install dependencies (macOS)

```shell
brew install pre-commit terraform terraform-docs
pre-commit install --install-hooks
```
