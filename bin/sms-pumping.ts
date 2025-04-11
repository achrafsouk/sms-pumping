#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { SMSPumpingStack } from '../lib/sms-pumping';

const app = new cdk.App();
new SMSPumpingStack(app, 'SMSPumpingStack', {
    env: {
        region: 'us-east-1',
    } 
    // explicitly set for Lambda@Edge
});