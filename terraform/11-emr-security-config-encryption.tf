################################################################################
# TRIGGER: emr/emr-security-configuration-encryption-rest
#          emr/emr-security-configuration-encryption-transit
# Policy:  Checks that EMR security configurations have encryption enabled
#
# BUG:     Both policies call:
#            config = core::jsondecode(attrs.configuration)
#          without any null guard. The 'configuration' attribute is a Required
#          JSON string in the Terraform schema. However, during:
#            - terraform plan -destroy  (attribute becomes null)
#            - resources created via 'terraform import' before full config
#          the attribute can be null, causing core::jsondecode(null) to panic.
#
# TRIGGER: Run 'terraform plan -destroy' on the resource below, or use
#          an import stub with configuration not yet specified.
################################################################################


# *** TRIGGER ***
# During 'terraform plan -destroy', attrs.configuration is null.
# The policy locals:
#   config = core::jsondecode(attrs.configuration)
# throws: "cannot decode null as JSON"
#
# Also triggered when importing an existing security configuration before
# the full 'configuration' attribute is known.
resource "aws_emr_security_configuration" "example" {
  name = "encryption-trigger"

  # Minimal configuration — the encrypt values are false (policy will fail
  # on the enforce condition), but more importantly, running 'terraform plan
  # -destroy' will set configuration = null and trigger the jsondecode panic.
  configuration = jsonencode({
    EncryptionConfiguration = {
      EnableInTransitEncryption = false
      EnableAtRestEncryption    = false
    }
  })
}
