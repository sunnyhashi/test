################################################################################
# TRIGGER: network-firewall/network-firewall-stateless-rule-group-not-empty
# Policy:  Checks that stateless Network Firewall rule groups have rules
#
# BUG:     The policy accesses three nested [0] indices inside core::try:
#            attrs.rule_group[0].rules_source[0]
#              .stateless_rules_and_custom_actions[0].stateless_rule
#          If any parent list is empty, [0] panics inside core::try.
#
# PROVIDER SCHEMA CONSTRAINTS (all min 1, cannot be omitted from HCL):
#   rule_group {}                            — optional on the resource
#   └─ rules_source {}                       — required (min 1)
#      └─ stateless_rules_and_custom_actions — required (min 1)
#         └─ stateless_rule {}               — required (min 1)
#
# Because every nested block is min-1, the null-check panic at the THIRD
# level cannot be triggered from HCL alone. The trigger is always a destroy
# plan, where the provider represents rule_group as [] in plan data.
#
# TRIGGER: Run 'terraform plan -destroy' on the resource below.
#   terraform plan -destroy -target=aws_networkfirewall_rule_group.stateless_with_rules
#
# The destroy plan sets rule_group = [] in the plan attributes.
# The policy local:
#   stateless_rule_list = core::try(
#     attrs.rule_group[0].rules_source[0]
#       .stateless_rules_and_custom_actions[0].stateless_rule, null
#   )
# panics on rule_group[0] because the list is empty.
################################################################################

provider "aws" {
  region = "us-east-1"
}

# Valid STATELESS rule group with one drop-all rule.
# Run 'terraform plan -destroy' to trigger the rule_group[0] panic.
resource "aws_networkfirewall_rule_group" "stateless_with_rules" {
  capacity = 100
  name     = "stateless-with-rules"
  type     = "STATELESS"

  rule_group {
    rules_source {
      stateless_rules_and_custom_actions {
        stateless_rule {
          priority = 1
          rule_definition {
            actions = ["aws:drop"]
            match_attributes {
              protocols = [6]
            }
          }
        }
      }
    }
  }
}
