################################################################################
# TRIGGER: codebuild/codebuild-project-source-repo-url-check
# Policy:  Checks Bitbucket source uses CODECONNECTIONS or SECRETS_MANAGER auth
#
# BUG:     The policy filter is:
#            filter = core::try(attrs.source[0].type, "") == "BITBUCKET"
#          The 'source' block is required by the Terraform provider but modeled
#          as a list. An empty source block produces source = [] and [0] panics.
#
# TRIGGER: An aws_codebuild_project where the source block body is empty,
#          or the source is being updated and temporarily empty in the plan.
################################################################################



data "aws_iam_policy_document" "assume" {
  statement {
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["codebuild.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "cb" {
  name               = "codebuild-source-role"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

# *** TRIGGER ***
# A CodeBuild project with source type = "BITBUCKET" passes the policy filter.
# During 'terraform plan -destroy' the source attribute becomes [] in the plan,
# and core::try(attrs.source[0].type, "") panics on source[0].
#
# Run: terraform plan -destroy -target=aws_codebuild_project.bitbucket_project
resource "aws_codebuild_project" "bitbucket_project" {
  name         = "bitbucket-project"
  service_role = aws_iam_role.cb.arn

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
    type     = "BITBUCKET"
    location = "https://bitbucket.org/example/repo.git"
    # auth block omitted — no CODECONNECTIONS or SECRETS_MANAGER auth,
    # which also fails the policy enforce condition (intended).
  }
}
