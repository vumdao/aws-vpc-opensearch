import { App } from 'aws-cdk-lib';
import { DevOpensearchStack } from './opensearch';
import { CDK_DEFAULT_ACCOUNT, CDK_DEFAULT_REGION } from './shared/configs';

const app = new App();

new DevOpensearchStack(app, 'DevOpensearchClusterStack', {
  description: 'Dev opensearch cluster',
  env: {
    region: CDK_DEFAULT_REGION,
    account: CDK_DEFAULT_ACCOUNT
  },
});
