data "aws_ami" "latest_ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Owner= Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

resource "aws_security_group" "test_1" {
  name = "test-1"
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group_rule" "sg_1_rule_1" {
  from_port         = 80
  protocol          = "tcp"
  to_port           = 80
  security_group_id = aws_security_group.test_1.id
  cidr_blocks       = ["0.0.0.0/0"]
  type              = "ingress"
}

resource "aws_security_group_rule" "sg_1_rule_2" {
  from_port         = 443
  protocol          = "tcp"
  to_port           = 443
  security_group_id = aws_security_group.test_1.id
  cidr_blocks       = ["0.0.0.0/0"]
  type              = "ingress"
}

resource "aws_security_group" "test_2" {
  name = "test-2"
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group_rule" "sg_2_rule_1" {
  from_port         = 8080
  protocol          = "tcp"
  to_port           = 8080
  security_group_id = aws_security_group.test_2.id
  type              = "ingress"
}

resource "aws_instance" "test_1" {
  ami                    = data.aws_ami.latest_ubuntu.id
  instance_type          = "t2.nano"
  vpc_security_group_ids = [aws_security_group.test_1.id, aws_security_group.test_2.id]
  tags = {
    Name = "test-1"
  }
}

output "security_group_test_1" {
  value = aws_security_group.test_1.id
}

output "security_group_test_2" {
  value = aws_security_group.test_2.id
}

output "aws_instance_test_1" {
  value = aws_instance.test_1.id
}
