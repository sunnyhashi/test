provider "aws" {
  region = "ap-south-1"
}

variable "queue_names" {
  type    = list(string)
  default = ["order-queue", "payment-queue", "notification-queue"]
}

resource "aws_sqs_queue" "queues" {
  for_each = toset(var.queue_names)

  name                       = each.value
  delay_seconds              = 0
  max_message_size           = 262144
  message_retention_seconds  = 345600
  visibility_timeout_seconds = 30

  tags = {
    Environment = "dev"
    ManagedBy   = "terraform"
  }
}

output "queue_urls" {
  value = {
    for q in aws_sqs_queue.queues :
    q.name => q.id
  }
}
