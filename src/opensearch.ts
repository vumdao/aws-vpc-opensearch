import { IdentityPool } from '@aws-cdk/aws-cognito-identitypool-alpha';
import { Stack, StackProps, RemovalPolicy, CfnOutput } from 'aws-cdk-lib';
import { CfnUserPoolGroup, UserPool } from 'aws-cdk-lib/aws-cognito';
import { EbsDeviceVolumeType, SecurityGroup, Vpc } from 'aws-cdk-lib/aws-ec2';
import { PolicyStatement, Role, ServicePrincipal, ArnPrincipal, FederatedPrincipal, AnyPrincipal } from 'aws-cdk-lib/aws-iam';
import { Domain, EngineVersion } from 'aws-cdk-lib/aws-opensearchservice';
import { Construct } from 'constructs';


export class DevOpensearchStack extends Stack {

  constructor(scope: Construct, id: string, props: StackProps) {
    super(scope, id, props);

    const prefix = 'dev-opensearch';

    const osVpc = new Vpc(this, `${prefix}-vpc`, {
      vpcName: prefix,
      natGateways: 1
    });

    const osSg = new SecurityGroup(this, `${prefix}-sg`, {
      securityGroupName: `${prefix}-sg`,
      vpc: osVpc
    });

    const userpool = new UserPool(this, `${prefix}-userpool`, {
      userPoolName: `${prefix}-userpool`,
      signInAliases: { username: false, email: true },
      standardAttributes: { email: { required: true } },
      removalPolicy: RemovalPolicy.DESTROY,
      selfSignUpEnabled: true
    });

    userpool.addDomain(`${prefix}-domain`, {
      cognitoDomain: { domainPrefix: 'devos' },
    });

    /**
     * This role gives Amazon OpenSearch Service permissions to configure the Amazon Cognito user and identity pools
     * and use them for OpenSearch Dashboards/Kibana authentication
     */
    const cognitoOpensearchRole = new Role(this, 'dev-CognitoAccessForAmazonOpenSearch', {
      roleName: 'dev-CognitoAccessForAmazonOpenSearch',
      assumedBy: new ServicePrincipal('opensearchservice.amazonaws.com'),
      managedPolicies: [{managedPolicyArn: 'arn:aws:iam::aws:policy/AmazonOpenSearchServiceCognitoAccess'}]
    });

    /**
     * Identity pools let you provide temporary, limited-priviledge AWS credentials to your users.
     * Attached to opensearch when enabling Amazon Cognito authentication
     */
    const identityPool = new IdentityPool(this, `${prefix}-identity-pool`, {
      identityPoolName: `${prefix}-identity`,
      allowUnauthenticatedIdentities: true
    });

    /**
     * Separate admin role for Fine-grained access control of opensearch
     * The role has no permission but inherit from domain level access policy
     * This role is used by opensearch admin group in cognito userpool.
     * In order to leverage this role, need some manual operation to switch identity pool
     * from `Use default role` to `Choose Role from Token
     * Ref: https://github.com/aws/aws-cdk/issues/21398
     */
    const adminAuthRole = new Role(this, `${prefix}-admin-auth-role`, {
      roleName: `${prefix}-admin-auth-role`,
      assumedBy: new FederatedPrincipal(
        'cognito-identity.amazonaws.com',
        {
          "StringEquals": {
            "cognito-identity.amazonaws.com:aud": identityPool.identityPoolId
          },
          "ForAnyValue:StringLike": {
              "cognito-identity.amazonaws.com:amr": "authenticated"
          }
        },
        'sts:AssumeRoleWithWebIdentity'
      )
    });

    /**
     * Currently only L1 construct
     * User group of admin user which use role from token instead of default role from identity pool
     */
    new CfnUserPoolGroup(this, `${prefix}-userpool-group`, {
      userPoolId: userpool.userPoolId,
      groupName: 'opensearch-admin-group',
      roleArn: adminAuthRole.roleArn,
      precedence: 0
    });

    const domainName = 'dev-opensearch';

    const osDomain = new Domain(this, domainName, {
      domainName: domainName,
      version: EngineVersion.OPENSEARCH_1_2,
      removalPolicy: RemovalPolicy.DESTROY,
      enableVersionUpgrade: true,
      vpc: osVpc,
      vpcSubnets: [{
        availabilityZones: [`${this.region}a`],
        onePerAz: true
      }],
      securityGroups: [osSg],
      capacity: {
        dataNodes: 1,
        dataNodeInstanceType: 't3.small.search',
      },
      ebs: {
        volumeSize: 10,
        volumeType: EbsDeviceVolumeType.GENERAL_PURPOSE_SSD,
      },
      cognitoDashboardsAuth: {
        identityPoolId: identityPool.identityPoolId,
        userPoolId: userpool.userPoolId,
        role: cognitoOpensearchRole
      },
      fineGrainedAccessControl: {
        masterUserArn: identityPool.authenticatedRole.roleArn
      },
      accessPolicies: [
        new PolicyStatement({
          actions: ['es:ESHttpGet', 'es:ESHttpPost'],
          resources: [`arn:aws:es:${this.region}:${this.account}:domain/${domainName}/*`],
          principals: [new ArnPrincipal(identityPool.authenticatedRole.roleArn)],
        }),
        new PolicyStatement({
          actions: ['es:*'],
          resources: [`arn:aws:es:${this.region}:${this.account}:domain/${domainName}/*`],
          principals: [new ArnPrincipal(adminAuthRole.roleArn)],
        }),

        /**
         * Support anonymous user
         * Some application/tool such as Kubernetes Event Exporter does not support IRSA but using basic authentication.
         * For using opensearch as a recevier, the tool just supports to use username/password
         * to communicate with opensearch domain, not support IRSA as aws-for-fluent-bit yet
         * Checkout: https://github.com/resmoio/kubernetes-event-exporter/issues/8
         */
        new PolicyStatement({
          actions: [
            "es:ESHttpDelete",
            "es:ESHttpPost",
            "es:ESHttpPut",
            "es:ESHttpPatch"
          ],
          resources: [`arn:aws:es:${this.region}:${this.account}:domain/${domainName}/kube-events*`],
          principals: [new AnyPrincipal()],
        })
      ],
      encryptionAtRest: {
        enabled: true,
      },
      enforceHttps: true,
      nodeToNodeEncryption: true
    });

    new CfnOutput(this, `${domainName}-output`, {
      description: 'Opensearch Domain Endpoint',
      value: `https://${osDomain.domainEndpoint}`
    });
  }
}
