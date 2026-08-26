################################################################################
# TRIGGER: ec2/ec2-launch-template-imdsv2-check
# Policy:  Checks that launch templates require IMDSv2 (http_tokens = "required")
#
# BUG:     The policy accesses attrs.metadata_options[0].http_tokens inside
#          core::try. The 'metadata_options' block is optional. A launch
#          template without it produces metadata_options = [].
#          Indexing [0] on [] panics inside core::try.
#
# TRIGGER: An aws_launch_template resource with NO metadata_options block.
################################################################################

provider "aws" {
  region = "us-east-1"
}

# *** TRIGGER ***
# No 'metadata_options' block is defined.
# The provider returns metadata_options = [] in the plan.
# The policy condition:
#   condition = core::try(attrs.metadata_options[0].http_tokens, "optional") == "required"
# panics on metadata_options[0] because the list is empty.
resource "aws_launch_template" "no_metadata_options" {
  name          = "no-metadata-options-lt"
  instance_type = "t3.micro"
  image_id      = "ami-0c02fb55956c7d316" # Amazon Linux 2 us-east-1

  # metadata_options block intentionally omitted
  # This means http_tokens defaults to "optional" on the instance,
  # AND the policy panics trying to evaluate it.
}
