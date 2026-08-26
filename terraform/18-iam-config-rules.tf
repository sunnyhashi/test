################################################################################
# TRIGGER: iam/access-keys-rotated
#          iam/iam-user-unused-credentials-check
# Policy:  Validates that the corresponding AWS Config managed rules exist
#          with correct source identifiers and parameters
#
# BUG:     Both policies access attrs.source[0].source_identifier and
#          attrs.source[0].owner inside core::try, without a length guard.
#          source is required by the provider, but during a destroy plan
#          source = [] in the plan data — [0] on [] panics inside core::try.
#
# TRIGGER: Run 'terraform plan -destroy' on the resources below.
#   terraform plan -destroy
#
# The destroy plan sets attrs.source = [] which triggers:
#   source_identifier = core::try(attrs.source[0].source_identifier, "")  <-- panic
################################################################################



# *** TRIGGER: access-keys-rotated ***
# Valid AWS-managed Config rule. Run 'terraform plan -destroy' to trigger
# the source[0] panic — the destroy plan sets source = [].
resource "aws_config_config_rule" "access_keys_rotated" {
  name = "access-keys-rotated"

  source {
    owner             = "AWS"
    source_identifier = "ACCESS_KEYS_ROTATED"
  }

  input_parameters = jsonencode({ maxAccessKeyAge = 90 })
}

# *** TRIGGER: iam-user-unused-credentials-check ***
resource "aws_config_config_rule" "iam_user_unused_credentials_check" {
  name = "iam-user-unused-credentials-check"

  source {
    owner             = "AWS"
    source_identifier = "IAM_USER_UNUSED_CREDENTIALS_CHECK"
  }

  input_parameters = jsonencode({ maxCredentialUsageAge = 90 })
}
