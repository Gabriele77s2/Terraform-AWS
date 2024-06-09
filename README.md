# terraform-aws

## Overview

This documentation provides a step-by-step guide to building a comprehensive AWS infrastructure using Terraform. The infrastructure includes:

- VPC and Subnets (public and private)
- Internet Gateway (IGW) and NAT Gateway
- Security Groups and Network Access Control Lists (NACLs)
- EC2 Instances and Auto Scaling Groups
- Load Balancers
- RDS Instances
- Amazon Elastic Kubernetes Service (EKS)
- AWS Fargate for serverless container deployment
- Route 53 for DNS management
- Best security practices and encryption

## Prerequisites

1. **Terraform**: Ensure you have Terraform installed. You can download it from [Terraform's official site](https://www.terraform.io/downloads.html).
2. **AWS CLI**: Install and configure AWS CLI with your credentials.
3. **IAM Role**: Ensure you have an IAM role with sufficient permissions to create and manage AWS resources.

## Project Structure

Create a directory for your Terraform configuration files. Below is a recommended structure:

```
my-aws-infrastructure/
├── provider.tf
├── network.tf
├── security_groups.tf
├── rds.tf
├── ec2_asg.tf
├── load_balancer.tf
├── eks.tf
├── fargate.tf
└── variables.tf
```

## Terraform Configuration Files

### 1. Provider and Backend Configuration

```hcl
# provider.tf

# Configure the AWS provider with the specified region.
# This tells Terraform to use AWS as the provider and operate in the "us-west-2" region.
provider "aws" {
  region = "us-west-2"
}

# Configure Terraform backend to store the state file in an S3 bucket.
# The backend block configures where Terraform will store its state file, which keeps track of the resources it manages.
terraform {
  backend "s3" {
    bucket         = "your-terraform-state-bucket"  # The name of your S3 bucket for storing the state file.
    key            = "terraform/state"              # The path within the bucket to store the state file.
    region         = "us-west-2"                    # The AWS region where the S3 bucket is located.
    dynamodb_table = "terraform-lock"               # DynamoDB table for state locking to prevent concurrent changes.
  }
}
```

### 2. VPC and Subnets

```hcl
# network.tf

# Create a VPC with the specified CIDR block.
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"  # Define the IP address range for the VPC.

  tags = {
    Name = "main-vpc"  # Tag the VPC with a name for identification.
  }
}

# Create public subnets.
resource "aws_subnet" "public" {
  count = 2  # Create two public subnets.
  vpc_id     = aws_vpc.main.id  # Associate the subnets with the VPC.
  cidr_block = "10.0.${count.index}.0/24"  # Define the IP address range for each subnet.
  availability_zone = element(var.availability_zones, count.index)  # Assign each subnet to a different availability zone.

  map_public_ip_on_launch = true  # Automatically assign public IPs to instances launched in these subnets.

  tags = {
    Name = "public-subnet-${count.index}"  # Tag the subnets with a name for identification.
  }
}

# Create private subnets.
resource "aws_subnet" "private" {
  count = 2  # Create two private subnets.
  vpc_id     = aws_vpc.main.id  # Associate the subnets with the VPC.
  cidr_block = "10.0.${count.index + 2}.0/24"  # Define the IP address range for each subnet.
  availability_zone = element(var.availability_zones, count.index)  # Assign each subnet to a different availability zone.

  tags = {
    Name = "private-subnet-${count.index}"  # Tag the subnets with a name for identification.
  }
}

# Create an Internet Gateway for the VPC.
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id  # Associate the Internet Gateway with the VPC.

  tags = {
    Name = "main-igw"  # Tag the Internet Gateway with a name for identification.
  }
}

# Create NAT Gateways for outbound internet access from private subnets.
resource "aws_nat_gateway" "nat" {
  count = 2
  allocation_id = aws_eip.nat[count.index].id  # Associate the NAT Gateway with an Elastic IP.
  subnet_id     = aws_subnet.public[count.index].id  # Place the NAT Gateway in a public subnet.

  tags = {
    Name = "nat-gateway-${count.index}"  # Tag the NAT Gateway with a name for identification.
  }
}

# Allocate Elastic IPs for the NAT Gateways.
resource "aws_eip" "nat" {
  count = 2
  vpc = true  # Specify that these Elastic IPs are for use in a VPC.
}

# Create a public route table.
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id  # Associate the route table with the VPC.

  route {
    cidr_block = "0.0.0.0/0"  # Route all traffic to the Internet Gateway.
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = "public-route-table"  # Tag the route table with a name for identification.
  }
}

# Associate public subnets with the public route table.
resource "aws_route_table_association" "public" {
  count          = 2
  subnet_id      = aws_subnet.public[count.index].id  # Associate each public subnet with the route table.
  route_table_id = aws_route_table.public.id
}

# Create private route tables.
resource "aws_route_table" "private" {
  count = 2
  vpc_id = aws_vpc.main.id  # Associate the route table with the VPC.

  route {
    cidr_block = "0.0.0.0/0"  # Route all traffic to the NAT Gateway.
    nat_gateway_id = aws_nat_gateway.nat[count.index].id
  }

  tags = {
    Name = "private-route-table-${count.index}"  # Tag the route table with a name for identification.
  }
}

# Associate private subnets with the private route tables.
resource "aws_route_table_association" "private" {
  count          = 2
  subnet_id      = aws_subnet.private[count.index].id  # Associate each private subnet with the route table.
  route_table_id = aws_route_table.private[count.index].id
}
```

### 3. Security Groups

```hcl
# security_groups.tf

# Security group for web servers.
resource "aws_security_group" "web_sg" {
  vpc_id = aws_vpc.main.id  # Associate the security group with the VPC.

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Allow HTTP traffic from anywhere.
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Allow HTTPS traffic from anywhere.
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"  # -1 means all protocols.
    cidr_blocks = ["0.0.0.0/0"]  # Allow all outbound traffic.
  }

  tags = {
    Name = "web-sg"  # Tag the security group with a name for identification.
  }
}

# Security group for database servers.
resource "aws_security_group" "db_sg" {
  vpc_id = aws_vpc.main.id  # Associate the security group with the VPC.

  ingress {
    from_port         = 5432  # PostgreSQL port.
    to_port           = 5432
    protocol          = "tcp"
    security_groups   = [aws_security_group.web_sg.id]  # Allow traffic from web servers.
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"  # -1 means all protocols.
    cidr_blocks = ["0.0.0.0/0"]  # Allow all outbound traffic.
  }

  tags = {
    Name = "db-sg"  # Tag the security group with a name for identification.
  }
}
```

### 4. RDS Instance

```hcl
# rds.tf

# Create a PostgreSQL RDS instance.
resource "aws_db_instance" "default" {
  allocated_storage    = 20  # The size of the database (in GB).
  storage_type         = "gp2"  # General purpose SSD storage.
  engine               = "postgres"  # Use PostgreSQL as the database engine.
  engine_version       = "13.3"  # Version of PostgreSQL.
  instance_class       = "db.t3.micro"  # The type of database instance.
  name                 = "mydb"  # The name of the database.
  username             = "admin"  # The master username.
  password             = "yourpassword"  # The master password (replace with a secure password).
  parameter_group_name = "default.postgres13"  # Parameter group for PostgreSQL.
  skip_final_snapshot  = true  # Skip creating a final snapshot when the database is deleted.
  vpc_security_group_ids = [aws_security_group.db_sg.id]  # Assign the database security group.

  tags = {
    Name = "mydb-instance"  # Tag the RDS instance with a name for identification.
  }
}
```

### 5. EC2 Instances and Auto Scaling

```hcl
# ec2_asg.tf

# Launch configuration for EC2 instances.
resource "aws_launch_configuration" "app" {
  name          = "app-launch-configuration"  # Name of the launch configuration.
  image_id      = "ami-0c55b159cbfafe1f0"  # The ID of the AMI to use (replace with a valid AMI ID).
  instance_type = "t2.micro"  # The type of instance.
  security_groups = [aws_security_group.web_sg.id]  # Assign the web security group.
  key_name      = "your-key-pair"  # Replace with your EC2 key pair to access the instances via SSH.

  # Ensure the launch configuration is created before destroying the old one.
  lifecycle {
    create_before_destroy = true
  }
}

# Auto Scaling Group for EC2 instances.
resource "aws_autoscaling_group" "app" {
  desired_capacity     = 2  # The number of instances the group should have.
  max_size             = 3  # The maximum number of instances.
  min_size             = 1  # The minimum number of instances.
  vpc_zone_identifier  = aws_subnet.public[*].id  # The subnets where the instances will be launched.
  launch_configuration = aws_launch_configuration.app.id  # Use the defined launch configuration.

  # Tag the instances with a name for identification.
  tag {
    key                 = "Name"
    value               = "app-instance"
    propagate_at_launch = true
  }
}
```

### 6. Load Balancer

```hcl
# load_balancer.tf

# Create an Application Load Balancer.
resource "aws_lb" "app" {
  name               = "app-lb"  # The name of the load balancer.
  internal           = false  # Set to false to create an internet-facing load balancer.
  load_balancer_type = "application"  # The type of load balancer.
  security_groups    = [aws_security_group.web_sg.id]  # Assign the web security group.
  subnets            = aws_subnet.public[*].id  # Place the load balancer in the public subnets.

  tags = {
    Name = "app-lb"  # Tag the load balancer with a name for identification.
  }
}

# Target group for the load balancer.
resource "aws_lb_target_group" "app" {
  name     = "app-tg"  # The name of the target group.
  port     = 80  # The port on which the targets receive traffic.
  protocol = "HTTP"  # The protocol for connections from clients to the load balancer.
  vpc_id   = aws_vpc.main.id  # Associate the target group with the VPC.

  # Health check configuration for the targets.
  health_check {
    path                = "/"  # The destination for health checks.
    interval            = 30   # The approximate interval, in seconds, between health checks of an individual target.
    timeout             = 5    # The amount of time, in seconds, during which no response means a failed health check.
    healthy_threshold   = 2    # The number of consecutive health checks successes required before considering an unhealthy target healthy.
    unhealthy_threshold = 2    # The number of consecutive health check failures required before considering a target unhealthy.
  }
}

# Listener for the load balancer.
resource "aws_lb_listener" "app" {
  load_balancer_arn = aws_lb.app.arn  # The ARN of the load balancer to associate the listener with.
  port              = "80"  # The port on which the load balancer is listening.
  protocol          = "HTTP"  # The protocol for connections from clients to the load balancer.

  # Default action to forward requests to the target group.
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}

# Attach the Auto Scaling Group to the load balancer target group.
resource "aws_autoscaling_attachment" "asg_attachment" {
  autoscaling_group_name = aws_autoscaling_group.app.name  # The name of the Auto Scaling Group.
  alb_target_group_arn   = aws_lb_target_group.app.arn  # The ARN of the target group.
}
```

### 7. EKS Cluster

```hcl
# eks.tf

# Create an EKS cluster using a Terraform module.
module "eks" {
  source          = "terraform-aws-modules/eks/aws"  # Use the EKS module from the Terraform registry.
  cluster_name    = "my-cluster"  # The name of the EKS cluster.
  cluster_version = "1.21"  # The version of the EKS cluster.
  subnets         = aws_subnet.private[*].id  # Place the EKS cluster in the private subnets.
  vpc_id          = aws_vpc.main.id  # Associate the EKS cluster with the VPC.

  # Define the worker nodes configuration.
  node_groups = {
    eks_nodes = {
      desired_capacity = 2  # The desired number of worker nodes.
      max_capacity     = 3  # The maximum number of worker nodes.
      min_capacity     = 1  # The minimum number of worker nodes.
      instance_type    = "t3.medium"  # The instance type for the worker nodes.
      key_name         = "your-key-pair"  # Replace with your EC2 key pair to access the instances via SSH.
    }
  }

  tags = {
    Environment = "production"  # Tag the EKS resources with an environment name.
  }
}
```

### 8. Fargate Deployment

```hcl
# fargate.tf

# Create an ECS cluster for Fargate.
resource "aws_ecs_cluster" "main" {
  name = "fargate-cluster"  # The name of the ECS cluster.
}

# Define the task execution IAM role.
resource "aws_iam_role" "ecs_task_execution_role" {
  name = "ecs_task_execution_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })

  # Attach the AmazonECSTaskExecutionRolePolicy policy to the role.
  managed_policy_arns = [
    "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy",
  ]
}

# Create a Fargate task definition.
resource "aws_ecs_task_definition" "app" {
  family                   = "fargate-task"  # The name of the task definition.
  network_mode             = "awsvpc"  # The network mode to use for the containers.
  requires_compatibilities = ["FARGATE"]  # Specify Fargate launch type.
  cpu                      = "256"  # The number of CPU units used by the task.
  memory                   = "512"  # The amount of memory (in MiB) used by the task.

  execution_role_arn = aws_iam_role.ecs_task_execution_role.arn  # The ARN of the task execution role.

  container_definitions = jsonencode([
    {
      name  = "app"
      image = "nginx"  # Replace with your application container image.
      essential = true
      portMappings = [
        {
          containerPort = 80
          hostPort      = 80
        }
      ]
    }
  ])
}

# Create an ECS service to run the task.
resource "aws_ecs_service" "app" {
  name            = "fargate-service"
  cluster         = aws_ecs_cluster.main.id  # The ID of the ECS cluster.
  task_definition = aws_ecs_task_definition.app.arn  # The ARN of the task definition.
  desired_count   = 2  # The number of tasks to run.

  network_configuration {
    subnets          = aws_subnet.private[*].id  # Place the tasks in the private subnets.
    security_groups  = [aws_security_group.web_sg.id]  # Assign the web security group.
    assign_public_ip = false  # Do not assign public IPs to the tasks.
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.app.arn  # The ARN of the target group.
    container_name   = "app"
    container_port   = 80
  }
}
```

### 9. Route 53 DNS

```hcl
# route53.tf

# Create a Route 53 hosted zone.
resource "aws_route53_zone" "main" {
  name = "example.com"  # Replace with your domain name.
}

# Create a DNS record for the load balancer.
resource "aws_route53_record" "app" {
  zone_id = aws_route53_zone.main.id  # The ID of the Route 53 hosted zone.
  name    = "app.example.com"  # Replace with your subdomain name.
  type    = "A"

  alias {
    name                   = aws_lb.app.dns_name  # The DNS name of the load balancer.
    zone_id                = aws_lb.app.zone_id  # The zone ID of the load balancer.
    evaluate_target_health = true
  }
}
```

### 10. Network ACLs

```hcl
# nacl.tf

# Create a Network ACL for the public subnets.
resource "aws_network_acl" "public" {
  vpc_id = aws_vpc.main.id  # Associate the NACL with the VPC.

  # Inbound rule to allow HTTP traffic.
  ingress {
    rule_no    = 100
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 80
    to_port    = 80
  }

  # Inbound rule to allow HTTPS

 traffic.
  ingress {
    rule_no    = 110
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 443
    to_port    = 443
  }

  # Outbound rule to allow all traffic.
  egress {
    rule_no    = 100
    protocol   = "-1"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  tags = {
    Name = "public-nacl"  # Tag the NACL with a name for identification.
  }
}

# Associate the public NACL with the public subnets.
resource "aws_network_acl_association" "public" {
  count          = 2
  subnet_id      = aws_subnet.public[count.index].id  # Associate each public subnet with the NACL.
  network_acl_id = aws_network_acl.public.id
}

# Create a Network ACL for the private subnets.
resource "aws_network_acl" "private" {
  vpc_id = aws_vpc.main.id  # Associate the NACL with the VPC.

  # Inbound rule to allow all traffic from the VPC.
  ingress {
    rule_no    = 100
    protocol   = "-1"
    action     = "allow"
    cidr_block = aws_vpc.main.cidr_block
    from_port  = 0
    to_port    = 0
  }

  # Outbound rule to allow all traffic.
  egress {
    rule_no    = 100
    protocol   = "-1"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  tags = {
    Name = "private-nacl"  # Tag the NACL with a name for identification.
  }
}

# Associate the private NACL with the private subnets.
resource "aws_network_acl_association" "private" {
  count          = 2
  subnet_id      = aws_subnet.private[count.index].id  # Associate each private subnet with the NACL.
  network_acl_id = aws_network_acl.private.id
}
```

### 11. Variables and Outputs

Create `variables.tf` to define all necessary variables.

```hcl
# variables.tf

# List of availability zones to use.
variable "availability_zones" {
  type    = list(string)
  default = ["us-west-2a", "us-west-2b"]  # Replace with your availability zones.
}

# The domain name for Route 53.
variable "domain_name" {
  type    = string
  default = "example.com"  # Replace with your domain name.
}
```

Create `outputs.tf` to define outputs that you want to retrieve after applying the Terraform configuration.

```hcl
# outputs.tf

# Output the VPC ID.
output "vpc_id" {
  value = aws_vpc.main.id
}

# Output the public subnet IDs.
output "public_subnets" {
  value = aws_subnet.public[*].id
}

# Output the private subnet IDs.
output "private_subnets" {
  value = aws_subnet.private[*].id
}

# Output the load balancer DNS name.
output "load_balancer_dns_name" {
  value = aws_lb.app.dns_name
}

# Output the EKS cluster endpoint.
output "eks_cluster_endpoint" {
  value = module.eks.cluster_endpoint
}
```

### Applying the Configuration

1. **Initialize Terraform**: Run `terraform init` to initialize your Terraform configuration. This will download necessary provider plugins and set up your backend configuration.

   ```sh
   terraform init
   ```

2. **Plan the Infrastructure**: Run `terraform plan` to see the execution plan for your infrastructure. This will show you what changes will be made without actually applying them.

   ```sh
   terraform plan
   ```

3. **Apply the Configuration**: Run `terraform apply` to create the resources defined in your configuration files. This will prompt you to confirm before proceeding.

   ```sh
   terraform apply
   ```

### Best Security Practices

- **Use IAM Roles and Policies**: Ensure that your AWS IAM roles and policies follow the principle of least privilege, granting only the necessary permissions.
- **Enable Encryption**: Use encrypted S3 buckets for Terraform state files and enable encryption for EBS volumes, RDS instances, and other storage resources.
- **Restrict Security Group Rules**: Minimize the use of wide open security group rules (e.g., `0.0.0.0/0`) and restrict access to specific IP ranges and ports.
- **Use Private Subnets**: Place sensitive resources in private subnets to limit their exposure to the internet.
- **Rotate Secrets**: Regularly rotate secrets, such as database passwords and API keys, and store them securely using AWS Secrets Manager or AWS Systems Manager Parameter Store.
- **Monitor and Audit**: Implement logging and monitoring using AWS CloudTrail, AWS Config, and Amazon CloudWatch to track changes and monitor the health of your infrastructure.
