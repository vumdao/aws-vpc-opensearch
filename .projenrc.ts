import { awscdk } from "projen";
const project = new awscdk.AwsCdkTypeScriptApp({
  cdkVersion: "2.34.2",
  //cdkVersionPinning: true,
  defaultReleaseBranch: "master",
  name: "aws-eks-blueprints-cdk",
  projenrcTs: true,
  github: false,
  deps: [
    'env-var', 'dotenv',
    '@aws-cdk/aws-cognito-identitypool-alpha'
  ],

  // deps: [],                /* Runtime dependencies of this module. */
  // description: undefined,  /* The description is just a string that helps people understand the purpose of the package. */
  // devDeps: [],             /* Build dependencies for this module. */
  // packageName: undefined,  /* The "name" in package.json. */
});

const dotEnvFile = '.env'
project.gitignore.addPatterns(dotEnvFile)
project.gitignore.addPatterns('node_modules')

project.synth();