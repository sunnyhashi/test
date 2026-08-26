################################################################################
# TRIGGER: s3/s3-bucket-blacklisted-actions-prohibited
#          s3/s3-bucket-level-public-access-prohibited
#          s3/s3-mrap-public-access-blocked
# Policy:  Various S3 security checks
#
# BUGS:
#   1. s3-bucket-blacklisted-actions-prohibited:
#      policy_doc = core::jsondecode(attrs.policy)
#      No null guard. During a destroy plan or when the policy attribute has not
#      yet been computed, attrs.policy is null and core::jsondecode(null) panics.
#
#   2. s3-bucket-level-public-access-prohibited:
#      public_access_block = core::getresources("aws_s3_bucket_public_access_block", {bucket = attrs.id})
#      block_public_acls   = core::try(local.public_access_block[0].block_public_acls, false)
#      If no aws_s3_bucket_public_access_block resource exists for this bucket,
#      core::getresources returns []. Then public_access_block[0] panics.
#
#   3. s3-mrap-public-access-blocked:
#      public_access_block = core::try(attrs.details[0].public_access_block, null)
#      block_public_acls   = core::try(local.public_access_block[0].block_public_acls, true)
#      Two cascading [0] panics:
#        a) If details = [], attrs.details[0] panics.
#        b) If public_access_block = null (not a list), null[0] panics.
################################################################################

provider "aws" {
  region = "us-east-1"

  # Required for s3control resources
  default_tags {
    tags = { Environment = "test" }
  }
}

# *** TRIGGER 1: s3-bucket-blacklisted-actions-prohibited ***
# An aws_s3_bucket_policy in a destroy plan has policy = null.
# The policy does: policy_doc = core::jsondecode(attrs.policy)
# which panics.
resource "aws_s3_bucket" "example" {
  bucket = "null-check-trigger-bucket-abc123"
}

# Uncomment to trigger jsondecode(null) — run 'terraform plan -destroy':
resource "aws_s3_bucket_policy" "trigger_jsondecode" {
  bucket = aws_s3_bucket.example.id

  # policy attribute is required, but when the resource is being destroyed,
  # attrs.policy becomes null in the plan — triggering core::jsondecode(null).
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = "*"
        Action    = ["s3:GetObject"]
        Resource  = "${aws_s3_bucket.example.arn}/*"
      }
    ]
  })
}

# *** TRIGGER 2: s3-bucket-level-public-access-prohibited ***
# An aws_s3_bucket WITHOUT a corresponding aws_s3_bucket_public_access_block.
# core::getresources("aws_s3_bucket_public_access_block", {bucket = attrs.id})
# returns [] (no such resource in the plan).
# Then: block_public_acls = core::try(local.public_access_block[0].block_public_acls, false)
# panics on [0] because public_access_block = [].
resource "aws_s3_bucket" "no_public_access_block" {
  bucket = "no-public-access-block-bucket-xyz789"

  # No aws_s3_bucket_public_access_block resource defined for this bucket.
  # The policy queries getresources() which returns [] — then [0] panics.
}

# *** TRIGGER 3: s3-mrap-public-access-blocked ***
# An aws_s3control_multi_region_access_point WITHOUT a public_access_block
# block inside the 'details' block. This produces:
#   attrs.details[0].public_access_block = null (not a list)
# Then local.public_access_block[0] panics because null[0] is invalid.
resource "aws_s3control_multi_region_access_point" "no_pab" {
  details {
    name = "no-pab-mrap"

    region {
      bucket = aws_s3_bucket.example.id
    }

    # public_access_block block intentionally omitted.
    # The policy:
    #   public_access_block = core::try(attrs.details[0].public_access_block, null)  --> null
    #   block_public_acls   = core::try(local.public_access_block[0].block_public_acls, true)
    # null[0] panics even inside core::try.
  }
}
