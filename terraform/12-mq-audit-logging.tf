################################################################################
# TRIGGER: mq/mq-cloudwatch-audit-log-enabled
# Policy:  Checks that ActiveMQ brokers have CloudWatch audit logging enabled
#
# BUG:     The policy accesses attrs.logs[0].audit inside core::try.
#          The 'logs' block is optional. An ActiveMQ broker without it
#          produces logs = [] in the plan. Indexing [0] on [] panics
#          even inside core::try.
#
# TRIGGER: An aws_mq_broker with engine_type = "ActiveMQ" and NO logs block.
################################################################################

# *** TRIGGER ***
# engine_type = "ActiveMQ" means the policy filter passes.
# No 'logs' block is defined, producing logs = [].
# The policy local:
#   audit_enabled_raw = core::try(attrs.logs[0].audit, false)
# panics on logs[0] because the list is empty.
resource "aws_mq_broker" "no_logs_block" {
  broker_name             = "no-logs-activemq"
  engine_type             = "ActiveMQ"
  engine_version          = "5.17.6"
  host_instance_type      = "mq.m5.large"
  security_groups         = ["sg-00000000000000000"]
  authentication_strategy = "simple"
  deployment_mode         = "SINGLE_INSTANCE"

  user {
    username = "admin"
    password = "MindTheGap1234!"
    console_access = true
  }

  # logs block intentionally omitted — produces logs = []
  # The policy panics at: audit_enabled_raw = core::try(attrs.logs[0].audit, false)
}
