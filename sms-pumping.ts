
import { AwsCustomResource, PhysicalResourceId, AwsCustomResourcePolicy } from 'aws-cdk-lib/custom-resources';
import { Construct } from 'constructs';
import * as cdk from 'aws-cdk-lib';
import * as apiGateway from 'aws-cdk-lib/aws-apigateway';
import * as cloudfront from 'aws-cdk-lib/aws-cloudfront';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as origins from 'aws-cdk-lib/aws-cloudfront-origins';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as waf from "aws-cdk-lib/aws-wafv2";
import * as s3deploy from 'aws-cdk-lib/aws-s3-deployment';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as iam from 'aws-cdk-lib/aws-iam';
import fs = require('fs');

export class SMSPumpingStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
        super(scope, id, props);

        // Read HTML from html directory
        var html = fs.readFileSync('html/index.html', 'utf8');

        // S3 bucket for serving the HTML
        const spaBucket = new s3.Bucket(this, 'spa-bucket', {
            blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
            encryption: s3.BucketEncryption.S3_MANAGED,
            versioned: true,
            removalPolicy: cdk.RemovalPolicy.DESTROY,
            autoDeleteObjects: true,
        });

        // Create Lambda + APIG gateway to serve the Phone validation API
        const path = require('node:path');
        const apiFunction = new lambda.Function(this, 'lamdaFunction', {
            runtime: lambda.Runtime.NODEJS_LATEST,
            handler: 'index.handler',
            code: lambda.Code.fromAsset(path.join(__dirname, '../lambda/origin')),
            architecture: lambda.Architecture.X86_64,
        });

        const api = new apiGateway.RestApi(this, "api", {
            endpointConfiguration: {
                types: [apiGateway.EndpointType.REGIONAL]
            }
        });

        const sms = api.root.addResource('api');
        sms.addMethod(
            'POST',
            new apiGateway.LambdaIntegration(apiFunction, { proxy: true }),
        );

        // Create WAF WebaCL to be attached to CloudFront
        const webACL = new waf.CfnWebACL(this, "SMSPumpingWebACL", {
            name: 'SMSPumpingWebACL',
            defaultAction: { allow: {} },
            scope: "CLOUDFRONT",
            visibilityConfig: {
                cloudWatchMetricsEnabled: true,
                metricName: "SMSPumpingWebACL",
                sampledRequestsEnabled: false,
            },
            rules: wafRules.map((wafRule) => wafRule.Rule),
        });

        // Create resources for the SMS pumping detection engine
        // First dynamodb tables
        const ipTable = new dynamodb.Table(this, "ipTable", {
            tableName: "sms-pumping-ip-table",
            partitionKey: {
                name: "ip",
                type: dynamodb.AttributeType.STRING
            },
            sortKey: {
                name: "rid",
                type: dynamodb.AttributeType.STRING
            },
            removalPolicy: cdk.RemovalPolicy.DESTROY,
        })
        const phoneTable = new dynamodb.Table(this, "phoneTable", {
            tableName: "sms-pumping-phone-table",
            partitionKey: {
                name: "phoneprefix",
                type: dynamodb.AttributeType.STRING
            },
            sortKey: {
                name: "rid",
                type: dynamodb.AttributeType.STRING
            },
            removalPolicy: cdk.RemovalPolicy.DESTROY,
        })

        const smsPumpingDetectionLambda = new cloudfront.experimental.EdgeFunction(this, 'smsPumpingDetectionLambda', {
            runtime: lambda.Runtime.NODEJS_LATEST,
            handler: 'index.handler',
            code: lambda.Code.fromAsset(path.join(__dirname, '../lambda/edge')),
            initialPolicy: [
                new iam.PolicyStatement({
                    actions: ['mobiletargeting:PhoneNumberValidate'],
                    resources: ['*'],
                  })
            ]
        });

        // Give Lambda the necessary permissions to make calls to DDB and Pinpoint
        ipTable.grantReadWriteData(smsPumpingDetectionLambda);
        phoneTable.grantReadWriteData(smsPumpingDetectionLambda);
        
        // Create CloudFront distro to serve both static and API traffic from same domain
        const cloudfrontDistribution = new cloudfront.Distribution(this, 'Distribution', {
            defaultRootObject: 'index.html',
            comment: 'SMS Pumping',
            minimumProtocolVersion: cloudfront.SecurityPolicyProtocol.TLS_V1_2_2018,
            defaultBehavior: {
                origin: origins.S3BucketOrigin.withOriginAccessControl(spaBucket, {
                    originAccessLevels: [cloudfront.AccessLevel.READ],
                }),
                viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                cachePolicy: cloudfront.CachePolicy.CACHING_OPTIMIZED
            },
            additionalBehaviors: {
                'api/*': {
                    origin: new origins.RestApiOrigin(api, {
                        originShieldEnabled: true,
                        originShieldRegion: 'us-east-1' // Force Lambda@Edge executions to be in a single region
                    }),
                    viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.HTTPS_ONLY,
                    cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
                    originRequestPolicy: cloudfront.OriginRequestPolicy.ALL_VIEWER_EXCEPT_HOST_HEADER,
                    allowedMethods: cloudfront.AllowedMethods.ALLOW_ALL,
                    edgeLambdas: [
                        {
                            functionVersion: smsPumpingDetectionLambda.currentVersion,
                            eventType: cloudfront.LambdaEdgeEventType.ORIGIN_REQUEST,
                            includeBody: true,
                        }
                    ]
                }
            },
            webAclId: webACL.attrArn
        });


        // create custom resource to get tge SDK URL of Bot Control in AWS WAF
        const customResourcePolicy = AwsCustomResourcePolicy.fromSdkCalls({
            resources: AwsCustomResourcePolicy.ANY_RESOURCE, // TODO: make it more restrictive
        });
        const wafIntegrationURLCustomResource = new AwsCustomResource(this, 'WAFWebACLproperties', {
            onUpdate: {
                service: 'WAFv2',
                action: 'GetWebACL',
                region: 'us-east-1',
                parameters: {
                    Id: webACL.attrId,
                    Name: 'SMSPumpingWebACL',
                    Scope: 'CLOUDFRONT'
                },
                outputPaths: ['ApplicationIntegrationURL'],
                physicalResourceId: PhysicalResourceId.of(`WAFWebACLproperties${Date.now().toString()}`),
            },
            policy: customResourcePolicy,
        });
        const wafIntegrationURL = wafIntegrationURLCustomResource.getResponseField('ApplicationIntegrationURL');


        // Replace the placeholder in the HTML with the Bot Control SDK URL, then deploy to S3 bucket
        html = html.replace('SDKPLACEHOLDER', wafIntegrationURL)

        new s3deploy.BucketDeployment(this, 'DeployWebsite', {
            sources: [s3deploy.Source.data('index.html', html)],
            destinationBucket: spaBucket,
            cacheControl: [s3deploy.CacheControl.fromString('max-age=5')],
        });

        // Outputs 
        new cdk.CfnOutput(this, 'S3 bucket hosting SPA HTML', { value: spaBucket.bucketName });
        new cdk.CfnOutput(this, 'SPA URL', {
            value: `https://${cloudfrontDistribution.distributionDomainName}`
        });
    }
}

const wafRules = [
    {
        Rule: {
            name: "block-malicious-ip",
            priority: 1,
            overrideAction: { none: {} },
            statement: {
                managedRuleGroupStatement: {
                    vendorName: "AWS",
                    name: "AWSManagedRulesAmazonIpReputationList",
                    ruleActionOverrides: [
                        {
                            name: "AWSManagedIPDDoSList",
                            actionToUse: { block: {} }
                        }
                    ]
                }
            },
            visibilityConfig: {
                sampledRequestsEnabled: true,
                cloudWatchMetricsEnabled: true,
                metricName: "block-malicious-ip",
            },
        },
    },
    {
        Rule: {
            name: "otp-verification-emit-label",
            priority: 3,
            statement: {
                byteMatchStatement: {
                    searchString: '/api/',
                    fieldToMatch: {
                        uriPath: {}
                    },
                    textTransformations: [
                        {
                            priority: 0,
                            type: 'LOWERCASE'
                        }
                    ],
                    positionalConstraint: 'EXACTLY'
                },
            },
            action: {
                count: {}
            },
            ruleLabels: [
                {
                    name: 'mylabels:otp'
                }
            ],
            visibilityConfig: {
                sampledRequestsEnabled: true,
                cloudWatchMetricsEnabled: true,
                metricName: "otp-verification-emit-label",
            },
        }
    },
    {
        Rule: {
            name: "validate-phone-format",
            priority: 4,
            action: { block: {} },
            statement: {
                andStatement: {
                    statements: [
                        {
                            labelMatchStatement: {
                                scope: 'LABEL',
                                key: 'mylabels:otp',
                            }
                        },
                        {
                            notStatement: {
                                statement: {
                                    regexMatchStatement: {
                                        regexString: "^\\+[1-9]\\d{1,14}$",
                                        fieldToMatch: {
                                            jsonBody: {
                                                matchPattern: {
                                                    includedPaths: ["/phone"]
                                                },
                                                matchScope: "ALL",
                                                invalidFallbackBehavior: "NO_MATCH",
                                                oversizeHandling: "NO_MATCH"
                                            }
                                        },
                                        textTransformations: [
                                            {
                                                priority: 0,
                                                type: "LOWERCASE"
                                            }
                                        ]
                                    }
                                }
                            }
                        }
                    ]
                }
            },
            visibilityConfig: {
                sampledRequestsEnabled: true,
                cloudWatchMetricsEnabled: true,
                metricName: "validate-phone-format",
            },
        },
    },
    {
        Rule: {
            name: "block-banned-ip-countries",
            priority: 5,
            action: { block: {} },
            statement: {
                andStatement: {
                    statements: [
                        {
                            labelMatchStatement: {
                                scope: 'LABEL',
                                key: 'mylabels:otp',
                            }
                        },
                        {
                            geoMatchStatement: {
                                countryCodes: [
                                    "BE", "SE"
                                ]
                            }

                        }
                    ]
                }
            },
            visibilityConfig: {
                sampledRequestsEnabled: true,
                cloudWatchMetricsEnabled: true,
                metricName: "block-banned-ip-countries",
            },
        },
    },
    {
        Rule: {
            name: "rate-limit-otp",
            priority: 6,
            statement: {
                rateBasedStatement: {
                    limit: 10,
                    evaluationWindowSec: 600,
                    aggregateKeyType: "IP",
                    scopeDownStatement: {
                        labelMatchStatement: {
                            scope: "LABEL",
                            key: "mylabels:otp"
                        }
                    }
                }
            },
            action: { block: {} },
            visibilityConfig: {
                sampledRequestsEnabled: true,
                cloudWatchMetricsEnabled: true,
                metricName: "rate-limit-otp",
            },
        }
    },

    {
        Rule: {
            name: "aws-bot-control",
            priority: 7,
            overrideAction: { none: {} },
            statement: {
                managedRuleGroupStatement: {
                    vendorName: "AWS",
                    name: "AWSManagedRulesBotControlRuleSet",
                    version: 'Version_3.1',
                    scopeDownStatement: {
                        labelMatchStatement: {
                            scope: 'LABEL',
                            key: 'mylabels:otp'
                        }
                    },
                    managedRuleGroupConfigs: [
                        {
                            awsManagedRulesBotControlRuleSet: {
                                inspectionLevel: "TARGETED",
                                enableMachineLearning: true,
                            }
                        }
                    ],
                    ruleActionOverrides: [
                        {
                            actionToUse: {
                                count: {}
                            },
                            name: 'CategoryAdvertising'
                        },
                        {
                            actionToUse: {
                                count: {}
                            },
                            name: 'CategoryArchiver'
                        },
                        {
                            actionToUse: {
                                count: {}
                            },
                            name: 'CategoryContentFetcher'
                        },
                        {
                            actionToUse: {
                                count: {}
                            },
                            name: 'CategoryEmailClient'
                        },
                        {
                            actionToUse: {
                                count: {}
                            },
                            name: 'CategoryHttpLibrary'
                        },
                        {
                            actionToUse: {
                                count: {}
                            },
                            name: 'CategoryLinkChecker'
                        },
                        {
                            actionToUse: {
                                count: {}
                            },
                            name: 'CategoryMiscellaneous'
                        },
                        {
                            actionToUse: {
                                count: {}
                            },
                            name: 'CategoryMonitoring'
                        },
                        {
                            actionToUse: {
                                count: {}
                            },
                            name: 'CategoryScrapingFramework'
                        },
                        {
                            actionToUse: {
                                count: {}
                            },
                            name: 'CategorySearchEngine'
                        },
                        {
                            actionToUse: {
                                count: {}
                            },
                            name: 'CategorySecurity'
                        },
                        {
                            actionToUse: {
                                count: {}
                            },
                            name: 'CategorySeo'
                        },
                        {
                            actionToUse: {
                                count: {}
                            },
                            name: 'CategorySocialMedia'
                        },
                        {
                            actionToUse: {
                                count: {}
                            },
                            name: 'CategoryAI'
                        },
                        {
                            actionToUse: {
                                count: {}
                            },
                            name: 'SignalAutomatedBrowser'
                        },
                        {
                            actionToUse: {
                                count: {}
                            },
                            name: 'SignalKnownBotDataCenter'
                        },
                        {
                            actionToUse: {
                                count: {}
                            },
                            name: 'SignalNonBrowserUserAgent'
                        },
                        {
                            actionToUse: {
                                count: {}
                            },
                            name: 'TGT_VolumetricIpTokenAbsent'
                        },
                        {
                            actionToUse: {
                                count: {}
                            },
                            name: 'TGT_TokenAbsent'
                        },
                        {
                            actionToUse: {
                                count: {}
                            },
                            name: 'TGT_VolumetricSession'
                        },
                        {
                            actionToUse: {
                                count: {}
                            },
                            name: 'TGT_VolumetricSessionMaximum'
                        },
                        {
                            actionToUse: {
                                count: {}
                            },
                            name: 'TGT_SignalAutomatedBrowser'
                        },
                        {
                            actionToUse: {
                                count: {}
                            },
                            name: 'TGT_SignalBrowserAutomationExtension'
                        },
                        {
                            actionToUse: {
                                count: {}
                            },
                            name: 'TGT_SignalBrowserInconsistency'
                        },
                        {
                            actionToUse: {
                                count: {}
                            },
                            name: 'TGT_ML_CoordinatedActivityLow'
                        },
                        {
                            actionToUse: {
                                count: {}
                            },
                            name: 'TGT_ML_CoordinatedActivityMedium'
                        },
                        {
                            actionToUse: {
                                count: {}
                            },
                            name: 'TGT_ML_CoordinatedActivityHigh'
                        },
                        {
                            actionToUse: {
                                count: {}
                            },
                            name: 'TGT_TokenReuseIpLow'
                        },
                        {
                            actionToUse: {
                                count: {}
                            },
                            name: 'TGT_TokenReuseIpMedium'
                        },
                        {
                            actionToUse: {
                                count: {}
                            },
                            name: 'TGT_TokenReuseIpHigh'
                        },
                        {
                            actionToUse: {
                                count: {}
                            },
                            name: 'TGT_TokenReuseCountryLow'
                        },
                        {
                            actionToUse: {
                                count: {}
                            },
                            name: 'TGT_TokenReuseCountryMedium'
                        },
                        {
                            actionToUse: {
                                count: {}
                            },
                            name: 'TGT_TokenReuseAsnLow'
                        },
                        {
                            actionToUse: {
                                count: {}
                            },
                            name: 'TGT_TokenReuseAsnHigh'
                        }
                    ]
                },
            },
            visibilityConfig: {
                sampledRequestsEnabled: true,
                cloudWatchMetricsEnabled: true,
                metricName: "aws-bot-control",
            },
        }
    },
    {
        Rule: {
            name: "block-request-with-no-valid-token",
            priority: 8,
            action: { block: {} },
            statement: {
                andStatement: {
                    statements: [
                        {
                            orStatement: {
                                statements: [
                                    {
                                        labelMatchStatement: {
                                            scope: 'LABEL',
                                            key: 'awswaf:managed:token:absent'
                                        }
                                    },
                                    {
                                        labelMatchStatement: {
                                            scope: 'LABEL',
                                            key: 'awswaf:managed:token:rejected'
                                        }
                                    }
                                ]
                            },
                        }, {
                            labelMatchStatement: {
                                scope: 'LABEL',
                                key: 'mylabels:otp'
                            }
                        }
                    ]
                }

            },
            visibilityConfig: {
                sampledRequestsEnabled: true,
                cloudWatchMetricsEnabled: true,
                metricName: "block-request-with-no-valid-token",
            },
        },
    },
    {
        Rule: {
            name: "send-signal-upstream-bot-signal",
            priority: 9,
            action: {
                count: {
                    customRequestHandling: {
                        insertHeaders: [
                            {
                                name: "bot-signal",
                                value: "bot-control"
                            }
                        ]
                    }
                }
            },
            statement: {
                orStatement: {
                    statements: [
                        {
                            labelMatchStatement: {
                                scope: "LABEL",
                                key: "awswaf:managed:aws:bot-control:targeted:aggregate:coordinated_activity:high"
                            }
                        },
                        {
                            labelMatchStatement: {
                                scope: "LABEL",
                                key: "awswaf:managed:aws:bot-control:targeted:aggregate:coordinated_activity:medium"
                            }
                        },
                        {
                            labelMatchStatement: {
                                scope: "LABEL",
                                key: "awswaf:managed:aws:bot-control:targeted:signal:automated_browser"
                            }
                        },
                        {
                            labelMatchStatement: {
                                scope: "LABEL",
                                key: "awswaf:managed:aws:bot-control:targeted:signal:browser_automation_extension"
                            }
                        },
                        {
                            labelMatchStatement: {
                                scope: "LABEL",
                                key: "awswaf:managed:aws:bot-control:targeted:signal:browser_inconsistency"
                            }
                        },
                        {
                            labelMatchStatement: {
                                scope: "LABEL",
                                key: "awswaf:managed:aws:bot-control:targeted:aggregate:volumetric:session:token_reuse:ip:high"
                            }
                        },
                        {
                            labelMatchStatement: {
                                scope: "LABEL",
                                key: "awswaf:managed:aws:bot-control:targeted:aggregate:volumetric:session:token_reuse:ip:medium"
                            }
                        },
                        {
                            labelMatchStatement: {
                                scope: "LABEL",
                                key: "awswaf:managed:aws:bot-control:targeted:aggregate:volumetric:session:token_reuse:country:high"
                            }
                        },
                        {
                            labelMatchStatement: {
                                scope: "LABEL",
                                key: "awswaf:managed:aws:bot-control:targeted:aggregate:volumetric:session:token_reuse:country:medium"
                            }
                        },
                        {
                            labelMatchStatement: {
                                scope: "LABEL",
                                key: "awswaf:managed:aws:bot-control:targeted:aggregate:volumetric:session:token_reuse:asn:high"
                            }
                        },
                        {
                            labelMatchStatement: {
                                scope: "LABEL",
                                key: "awswaf:managed:aws:bot-control:targeted:aggregate:volumetric:session:token_reuse:asn:medium"
                            }
                        },
                    ]
                }
            },
            visibilityConfig: {
                sampledRequestsEnabled: true,
                cloudWatchMetricsEnabled: true,
                metricName: "send-signal-upstream-bot-signal",
            },
        }
    },
    {
        Rule: {
            name: "send-signal-upstream-session-velocity-high",
            priority: 10,
            action: {
                count: {
                    customRequestHandling: {
                        insertHeaders: [
                            {
                                name: "session-velocity",
                                value: "high"
                            }
                        ]
                    }
                }
            },
            statement: {
                labelMatchStatement: {
                    scope: "LABEL",
                    key: "awswaf:managed:aws:bot-control:targeted:aggregate:volumetric:session:maximum"
                }

            },
            visibilityConfig: {
                sampledRequestsEnabled: true,
                cloudWatchMetricsEnabled: true,
                metricName: "send-signal-upstream-session-velocity-high",
            },
        }
    },
    {
        Rule: {
            name: "send-signal-upstream-session-velocity-medium",
            priority: 11,
            action: {
                count: {
                    customRequestHandling: {
                        insertHeaders: [
                            {
                                name: "session-velocity",
                                value: "medium"
                            }
                        ]
                    }
                }
            },
            statement: {
                labelMatchStatement: {
                    scope: "LABEL",
                    key: "awswaf:managed:aws:bot-control:targeted:aggregate:volumetric:session:high"
                }

            },
            visibilityConfig: {
                sampledRequestsEnabled: true,
                cloudWatchMetricsEnabled: true,
                metricName: "send-signal-upstream-session-velocity-medium",
            },
        }
    },
    {
        Rule: {
            name: "send-signal-upstream-session-velocity-low",
            priority: 12,
            action: {
                count: {
                    customRequestHandling: {
                        insertHeaders: [
                            {
                                name: "session-velocity",
                                value: "low"
                            }
                        ]
                    }
                }
            },
            statement: {
                labelMatchStatement: {
                    scope: "LABEL",
                    key: "awswaf:managed:aws:bot-control:targeted:aggregate:volumetric:session:medium"
                }

            },
            visibilityConfig: {
                sampledRequestsEnabled: true,
                cloudWatchMetricsEnabled: true,
                metricName: "send-signal-upstream-session-velocity-low",
            },
        }
    },
    {
        Rule: {
            name: "count-anonymyzing-ip",
            priority: 13,
            overrideAction: { none: {} },
            statement: {
                managedRuleGroupStatement: {
                    vendorName: "AWS",
                    name: "AWSManagedRulesAmazonIpReputationList",
                    ruleActionOverrides: [
                        {
                            name: "AnonymousIPList",
                            actionToUse: { count: {} }
                        },
                        {
                            name: "HostingProviderIPList",
                            actionToUse: { count: {} }
                        }
                    ]
                }
            },
            visibilityConfig: {
                sampledRequestsEnabled: true,
                cloudWatchMetricsEnabled: true,
                metricName: "count-anonymyzing-ip",
            },
        },
    },
    {
        Rule: {
            name: "send-signal-upstream-vpn-signal",
            priority: 14,
            action: {
                count: {
                    customRequestHandling: {
                        insertHeaders: [
                            {
                                name: "vpn-signal",
                                value: "aws-anonymous"
                            }
                        ]
                    }
                }
            },
            statement: {
                labelMatchStatement: {
                    scope: "LABEL",
                    key: "awswaf:managed:aws:anonymous-ip-list:AnonymousIPList"
                }

            },
            visibilityConfig: {
                sampledRequestsEnabled: true,
                cloudWatchMetricsEnabled: true,
                metricName: "send-signal-upstream-vpn-signal",
            },
        }
    },
    {
        Rule: {
            name: "send-signal-upstream-datacenter-signal",
            priority: 15,
            action: {
                count: {
                    customRequestHandling: {
                        insertHeaders: [
                            {
                                name: "datacenter-signal",
                                value: "aws-anonymous"
                            }
                        ]
                    }
                }
            },
            statement: {
                labelMatchStatement: {
                    scope: "LABEL",
                    key: "awswaf:managed:aws:anonymous-ip-list:HostingProviderIPList"
                }

            },
            visibilityConfig: {
                sampledRequestsEnabled: true,
                cloudWatchMetricsEnabled: true,
                metricName: "send-signal-upstream-datacenter-signal",
            },
        }
    }
];


