# threatstack-aws-dynamodb-writer

[![Build Status](https://travis-ci.org/ServerlessOpsIO/threatstack-aws-dynamodb-writer.svg?branch=master)](https://travis-ci.org/ServerlessOpsIO/threatstack-aws-dynamodb-writer) [![License](https://img.shields.io/badge/License-BSD%202--Clause-orange.svg)](https://opensource.org/licenses/BSD-2-Clause)

Receives messages from [Threat Stack AWS SNS publisher](https://github.com/ServerlessOpsIO/threatstack-aws-sns-publisher) (__REQUIRED__) and stores them in DynamoDB.

The service consists of:

* AWS Lambda function
* AWS DynamoDB table
* Permission resources to allow services to communicate

## Deployment
This service can be deployed using the button below which will redirect to CloudFormation.  You will need your Threat Stack API key, Org ID, User ID to deploy.

[![Launch CloudFormation Stack](https://s3.amazonaws.com/cloudformation-examples/cloudformation-launch-stack.png)](http://serverlessops-opensource-deploy-dev.s3-website-us-east-1.amazonaws.com/threatstack-aws-dynamodb-writer/CFN-DEPLOY-LATEST)

Alternatively, you can deploy from a clone of this repository by using [Serverless Framework](https://serverless.com/).

```
$ npm install -g serverless
$ npm install
$ serverless deploy -v
```

## Development
This repository uses Serverless Framework for managing the development life cycle.  To install Serverless Framework, ensure you have NodeJS and the [NPM](https://www.npmjs.com/get-npm) package manager installed.  Then perform the following.

```
$ npm install -g serverless
$ npm install
```

