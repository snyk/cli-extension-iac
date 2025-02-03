resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

variable "remote_user_addr" {
  type    = list(string)
  default = ["1.1.1.1/1"]
}

resource "aws_security_group" "vars" {
  vpc_id = aws_vpc.main.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.remote_user_addr
  }
}
