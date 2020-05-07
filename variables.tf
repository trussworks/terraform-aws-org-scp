variable "deny_root_account_target_ids" {
  description = "Target ids (AWS Account or Organizational Unit) to attach an SCP denying the root user from taking any action"
  type        = list(string)
  default     = []
}

variable "deny_leaving_orgs_target_ids" {
  description = "Target ids (AWS Account or Organizational Unit) to attach an SCP denying the ability to leave the AWS Organization"
  type        = list(string)
  default     = []
}

variable "deny_creating_iam_users_target_ids" {
  description = "Target ids (AWS Account or Organizational Unit) to attach an SCP denying the ability to create IAM users or Access Keys"
  type        = list(string)
  default     = []
}

variable "deny_deleting_kms_keys_target_ids" {
  description = "Target ids (AWS Account or Organizational Unit) to attach an SCP denying deleting KMS keys"
  type        = list(string)
  default     = []
}

variable "deny_deleting_route53_zones_target_ids" {
  description = "Target ids (AWS Account or Organizational Unit) to attach an SCP denying deleting Route53 Hosted Zones"
  type        = list(string)
  default     = []
}

variable "deny_all_access_target_ids" {
  description = "Target ids (AWS Account or Organizational Unit) to attach an SCP dening all access"
  type        = list(string)
  default     = []
}

variable "require_s3_encryption_target_ids" {
  description = "Target ids (AWS Account or Organizational Unit) to attach an SCP requiring S3 encryption"
  type        = list(string)
  default     = []
}

variable "deny_deleting_cloudwatch_logs_target_ids" {
  description = "Target ids (AWS Account or Organizational Unit) to attach an SCP denying deletion of CloudWatch, flowlogs,  log groups, or log streams"
  type        = list(string)
  default     = []
}

variable "protect_s3_bucket_target_ids" {
  description = "Target ids (AWS Account or Organizational Unit) to attach an SCP protecting S3 buckets and objects"
  type        = list(string)
  default     = []
}

variable "protect_s3_bucket_resources" {
  description = "S3 bucket resource ARNs to protect from bucket and object deletion"
  type        = list(string)
  default     = [""]
}

variable "protect_iam_role_target_ids" {
  description = "Target ids (AWS Account or Organizational Unit) to attach an SCP protecting IAM roles"
  type        = list(string)
  default     = []
}

variable "protect_iam_role_resources" {
  description = "IAM role resource ARNs to protect from modification and deletion"
  type        = list(string)
  default     = []
}

variable "restrict_regions_target_ids" {
  description = "Target ids (AWS Account or Organizational Unit) to attach an SCP restricting regions."
  type        = list(string)
  default     = []
}

variable "allowed_regions" {
  description = "AWS Regions allowed for use (for use with the restrict regions SCP)"
  type        = list(string)
  default     = [""]
}
