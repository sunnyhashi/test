################################################################################
# TRIGGER: ecs/ecs-containers-nonprivileged
#          ecs/ecs-task-definition-linux-user-non-root
#          ecs/ecs-task-definition-windows-user-non-admin
# Policy:  Checks ECS container definitions for privilege escalation issues
#
# BUG:     All three policies call:
#            core::jsondecode(attrs.container_definitions)
#          without a null guard. The 'container_definitions' attribute is a
#          Required JSON string in the AWS provider schema, but during a
#          destroy plan or a computed-unknown plan phase, the attribute value
#          is null. core::jsondecode(null) throws a runtime error.
#
#          Additionally, 'runtime_platform[0]' is accessed without checking
#          if the list is non-empty first.
#
# TRIGGER 1 (jsondecode null): A task definition in a destroy-only plan.
# TRIGGER 2 (runtime_platform[0]): A task definition with an empty
#            runtime_platform block.
################################################################################

# *** TRIGGER 1: jsondecode on null ***
# During 'terraform destroy', the plan represents container_definitions as null
# (the resource is being removed). The policy evaluates locals before the
# resource is filtered, calling core::jsondecode(null) which panics.
#
# Simulate a destroy plan:
#   terraform plan -destroy -target=aws_ecs_task_definition.example

resource "aws_ecs_task_definition" "example" {
  family = "null-check-trigger"

  container_definitions = jsonencode([
    {
      name      = "app"
      image     = "nginx:latest"
      cpu       = 256
      memory    = 512
      essential = true
    }
  ])
}

# *** TRIGGER 2: runtime_platform[0] on empty list ***
# 'runtime_platform' is optional. When the block is omitted, the Terraform
# AWS provider returns runtime_platform = [] in the plan.
# The policy filter:
#   filter = core::try(attrs.runtime_platform[0].operating_system_family, "LINUX") == "LINUX"
# panics on runtime_platform[0] because the list is empty.
resource "aws_ecs_task_definition" "no_runtime_platform" {
  family = "no-runtime-platform"

  container_definitions = jsonencode([
    {
      name      = "app"
      image     = "nginx:latest"
      cpu       = 256
      memory    = 512
      essential = true
      # 'user' omitted — would fail linux-user-non-root policy too, but the
      # runtime_platform[0] panic fires BEFORE we even reach that check
    }
  ])

  # runtime_platform block intentionally omitted — produces runtime_platform = []
  # which causes runtime_platform[0] panic in both:
  #   ecs-task-definition-linux-user-non-root
  #   ecs-task-definition-windows-user-non-admin
}
