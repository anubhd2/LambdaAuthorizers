# Lambda Authorizer Microservice For Hotel booking : AWS Lambda Authorizer

This Lambda function is a **custom API Gateway Authorizer** for the HotelAdmin system.  
It validates **JWT tokens** issued by Amazon Cognito, checks **user group membership**, and enforces API access policies dynamically.

---

## 🏗️ Architecture Overview

```text
        +----------------+
        | Client Request |
        +--------+-------+
                 |
                 v
      +------------------------+
      | API Gateway            |
      | (Custom Lambda Authorizer) |
      +----------+-------------+
                 |
                 v
       +------------------+
       | AWS Lambda Authorizer |
       | - Validate JWT         |
       | - Fetch public keys    |
       |   from Secrets Manager |
       | - Check Cognito groups |
       | - Return IAM policy    |
       +------------------+
