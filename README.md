# CloudShield

# Intelligent Cloud Cost & Security Optimization Platform

## Overview

CloudShield is a cloud-native web application designed to help organizations, developers, and students monitor their AWS cloud infrastructure for security vulnerabilities and unnecessary operational costs. The platform combines Cloud Security Posture Management (CSPM) and FinOps (Cloud Cost Optimization) into a single dashboard, enabling users to identify insecure configurations, optimize cloud resources, and receive actionable recommendations.

Unlike existing AWS services that require users to navigate multiple consoles, CloudShield provides a centralized platform for analyzing cloud resources, tracking security risks, monitoring infrastructure health, and estimating potential cost savings.

The application is initially developed using simulated AWS resources for safe testing and demonstration. In the final phase, it integrates with Amazon Web Services using the AWS SDK (Boto3) to perform real-time analysis of cloud resources.

---

# Problem it Solves

Cloud adoption has grown rapidly across organizations of all sizes. However, many cloud users unintentionally create security risks and incur unnecessary costs due to misconfigured resources or poor infrastructure management.

Some common issues include:

- Publicly accessible Amazon S3 buckets exposing sensitive information.
- EC2 instances running continuously despite minimal utilization.
- Unattached EBS volumes and old snapshots increasing storage costs.
- IAM users without Multi-Factor Authentication (MFA).
- Security Groups exposing sensitive ports such as SSH (22) or RDP (3389) to the public.
- Publicly accessible RDS databases.
- Unexpected increases in AWS bills caused by forgotten resources.

Although AWS provides several services to monitor these aspects individually, managing them requires technical expertise and switching between multiple dashboards. CloudShield addresses this challenge by offering a unified interface that evaluates both security posture and cost efficiency while providing easy-to-understand recommendations.

---

# Target Users (Personas)

## 1. Cloud Administrator

**Responsibilities**

- Manage AWS infrastructure.
- Monitor cloud resources.
- Ensure secure cloud configurations.

**Goals**

- Identify security vulnerabilities quickly.
- Optimize cloud resource utilization.
- Reduce operational costs.

---

## 2. DevOps Engineer

**Responsibilities**

- Deploy and maintain cloud applications.
- Manage CI/CD pipelines.
- Monitor infrastructure performance.

**Goals**

- Detect cloud misconfigurations.
- Improve infrastructure reliability.
- Optimize resource allocation.

---

## 3. Security Analyst

**Responsibilities**

- Monitor cloud security posture.
- Investigate security alerts.
- Ensure compliance with security best practices.

**Goals**

- Detect vulnerable cloud resources.
- Prioritize security risks.
- Generate security reports.

---

## 4. Startup Founder / Small Business Owner

**Responsibilities**

- Manage cloud infrastructure with limited budgets.

**Goals**

- Reduce AWS spending.
- Improve infrastructure security.
- Monitor cloud resources without requiring specialized cloud expertise.

---

## 5. Students & Cloud Learners

**Responsibilities**

- Learn AWS cloud services.
- Build and deploy cloud applications.

**Goals**

- Understand AWS best practices.
- Learn cloud security concepts.
- Avoid unnecessary cloud expenses while experimenting.

---

# Vision Statement

> **To provide an intelligent, secure, and cost-effective cloud optimization platform that enables organizations, developers, and students to build well-architected AWS environments by continuously monitoring security posture, identifying cost optimization opportunities, and delivering actionable recommendations through a simple and intuitive dashboard.**

---

# Key Features / Goals

## Cloud Security Monitoring

- Detect publicly accessible S3 buckets.
- Identify insecure Security Groups.
- Monitor IAM users without MFA.
- Detect unencrypted storage resources.
- Evaluate cloud security posture.
- Generate security risk scores.

---

## Cloud Cost Optimization

- Detect idle EC2 instances.
- Identify unattached EBS volumes.
- Detect unused Elastic IP addresses.
- Monitor storage utilization.
- Estimate monthly cloud costs.
- Calculate potential cost savings.

---

## Cloud Resource Inventory

- View EC2 instances.
- View S3 buckets.
- View RDS databases.
- View IAM users and roles.
- Monitor cloud resources from a centralized dashboard.

---

## Recommendation Engine

Provide intelligent recommendations for:

- Security improvements.
- Cost reduction.
- Infrastructure optimization.
- AWS best practices.

---

## Reporting

Generate reports containing:

- Security findings.
- Cost optimization opportunities.
- Infrastructure summary.
- Risk assessment.

---

## Authentication & Access Control

- Secure user authentication.
- Role-based access control.
- JWT-based session management.

---

# Success Metrics

The success of CloudShield will be evaluated using measurable technical and user-focused metrics.

### Functional Metrics

- Successfully detects common cloud security misconfigurations.
- Identifies cloud resources contributing to unnecessary costs.
- Displays complete cloud resource inventory.
- Generates actionable optimization recommendations.

### Performance Metrics

- Dashboard loads within 3 seconds.
- API response time below 500 ms.
- System availability greater than 99% during testing.

### User Experience Metrics

- Users can complete a cloud scan within five steps.
- Security and cost reports are generated successfully.
- Dashboard presents information in a simple and intuitive manner.

---

# Assumptions

- Users possess basic knowledge of AWS cloud services.
- AWS credentials used for scanning have appropriate read-only permissions.
- Internet connectivity is available.
- The initial version supports Amazon Web Services only.
- Mock cloud resources will be used during development before integrating with real AWS services.

---

# Constraints

## Technical Constraints

- Project duration is limited to two months.
- AWS Free Tier will be used wherever possible.
- Backend will be developed using FastAPI.
- Frontend will be developed using Next.js and React.
- PostgreSQL will be used as the primary database.
- Docker will be used for local development and deployment.

## Business Constraints

- The platform focuses only on AWS cloud infrastructure.
- Premium AWS services are excluded to minimize project cost.
- AI-powered recommendations are considered an advanced enhancement rather than a core feature.

---

# Future Scope

- Multi-cloud support (Microsoft Azure and Google Cloud Platform).
- Kubernetes security monitoring.
- Infrastructure-as-Code (Terraform) analysis.
- Compliance auditing based on CIS Benchmarks, NIST, and ISO 27001.
- Predictive cloud cost forecasting using machine learning.
- Slack and Microsoft Teams integration.
- Real-time monitoring and automated remediation.
