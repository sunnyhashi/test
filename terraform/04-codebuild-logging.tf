################################################################################
# TRIGGER: codebuild/codebuild-project-logging-enabled
# Policy:  Checks that CodeBuild projects have at least one logging destination
#
# BUG:     The policy chain is:
#            logs_config       = core::try(attrs.logs_config, null)
#            cloudwatch_logs   = core::try(local.logs_config[0].cloudwatch_logs, null)
#
#          When the 'logs_config' block is omitted, core::try returns null (not []).
#          Then 'local.logs_config[0]' is equivalent to 'null[0]' — a panic.
#          Similarly for s3_logs[0].
#
# TRIGGER: An aws_codebuild_project with NO logs_config block defined.
################################################################################

provider "aws" {
  region = "us-east-1"
}

data "aws_iam_policy_document" "assume_role" {
  statement {
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["codebuild.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "codebuild" {
  name               = "codebuild-role"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
}

# *** TRIGGER ***
# No 'logs_config' block is defined.
# The policy does:
#   logs_config = core::try(attrs.logs_config, null)   --> null
#   cloudwatch_logs = core::try(local.logs_config[0].cloudwatch_logs, null)
# Since logs_config is null (not a list), null[0] panics even inside core::try.
resource "aws_codebuild_project" "no_logging" {
  name         = "no-logging-project"
  service_role = aws_iam_role.codebuild.arn

  artifacts {
    type = "NO_ARTIFACTS"
  }

  environment {
    compute_type                = "BUILD_GENERAL1_SMALL"
    image                       = "aws/codebuild/standard:5.0"
    type                        = "LINUX_CONTAINER"
    image_pull_credentials_type = "CODEBUILD"
  }

  source {
    type      = "NO_SOURCE"
    buildspec = "version: 0.2\nphases:\n  build:\n    commands:\n      - echo hello"
  }

  # logs_config intentionally omitted — triggers null[0] panic
}
