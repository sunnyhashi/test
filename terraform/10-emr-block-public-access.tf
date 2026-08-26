################################################################################
# TRIGGER: emr/emr-block-public-access
# Policy:  Checks that EMR block public access has the correct port range (22)
#
# BUG:     The policy accesses:
#            attrs.permitted_public_security_group_rule_range[0].min_range
#            attrs.permitted_public_security_group_rule_range[0].max_range
#          inside core::try. This block is optional — when 'block_public_security_group_rules'
#          is true but no port range blocks are defined, the attribute is [].
#          Indexing [0] on [] panics even inside core::try.
#
# TRIGGER: An aws_emr_block_public_access_configuration with
#          block_public_security_group_rules = true but NO
#          permitted_public_security_group_rule_range block.
################################################################################

provider "aws" {
  region = "us-east-1"
}

# *** TRIGGER ***
# block_public_security_group_rules = true means the policy evaluates
# is_permitted_range. But no 'permitted_public_security_group_rule_range'
# block is provided, so the list is []. The policy panics on:
#   core::try(attrs.permitted_public_security_group_rule_range[0].min_range, 0)
resource "aws_emr_block_public_access_configuration" "no_range_block" {
  block_public_security_group_rules = true

  # permitted_public_security_group_rule_range block intentionally omitted.
  # This means permitted_public_security_group_rule_range = [].
  # The policy condition:
  #   is_permitted_range = local.block_security_group_enabled ?
  #     (core::try(attrs.permitted_public_security_group_rule_range[0].min_range, 0) == 22 && ...)
  # panics on [0] because the list is empty.
}
