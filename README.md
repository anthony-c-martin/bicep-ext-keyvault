# bicep-ext-keyvault
Sample KeyVault Bicep Extension

## Build + Test Locally

### Rebuild the extension
These commands rebuild the types, publish the extension to the local file system, and updates the sample bicepconfig to point to the local extension.
```sh
./scripts/generate_types.sh
./scripts/publish.sh ./bin/bicep-ext-keyvault
jq '.extensions.keyvault="../bin/bicep-ext-keyvault"' ./samples/bicepconfig.json > ./samples/bicepconfig.new.json
mv ./samples/bicepconfig.new.json ./samples/bicepconfig.json
```

### Test the extension
Run the deployment.
```sh
~/.azure/bin/bicep local-deploy ./samples/basic/main.bicepparam
```

To enable verbose tracing, run the following beforehand.
```sh
export BICEP_TRACING_ENABLED=true
```

## Publishing to a registry
This repo is set up to automatically publish to an ACR on every push to the `main` branch. This is configured with GitHub Actions.

### First time setup
To configure the GitHub Actions automation for the first time:

Log in to Azure CLI. Customize and run `./scripts/initial_setup.sh`.

## Samples

See the [samples](./samples/) folder for information on how to test this out.

> [!NOTE]
> Extension binary packages are not currently signed. If you see the following error on Mac, you may need to manually sign the extension package:
> 
> `Failed to launch provider: Failed to connect to provider /Users/ant/.bicep/br/bicepextdemo.azurecr.io/extensions$keyvault/0.1.1$/extension.bin`
> 
> To work around it, run the following in a terminal window, using the path from the error message:
> 
> `codesign -s - '/Users/ant/.bicep/br/bicepextdemo.azurecr.io/extensions$keyvault/0.1.1$/extension.bin'`