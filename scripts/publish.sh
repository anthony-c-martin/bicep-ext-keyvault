#!/bin/bash
set -e

usage="Usage: ./publish.sh <target>"
target=${1:?"Missing target. ${usage}"}

root="$(dirname ${BASH_SOURCE[0]})/../src/Bicep.Extension.KeyVault"
types_index="$(dirname ${BASH_SOURCE[0]})/../types/index.json"
ext_name="bicep-ext-keyvault"

# build various flavors
dotnet publish --configuration release --self-contained true -r osx-arm64 $root
dotnet publish --configuration release --self-contained true -r linux-x64 $root
dotnet publish --configuration release --self-contained true -r win-x64 $root

# publish to the registry
~/.azure/bin/bicep publish-extension \
  $types_index \
  --bin-osx-arm64 "$root/bin/release/net8.0/osx-arm64/publish/$ext_name" \
  --bin-linux-x64 "$root/bin/release/net8.0/linux-x64/publish/$ext_name" \
  --bin-win-x64 "$root/bin/release/net8.0/win-x64/publish/$ext_name.exe" \
  --target "$target" \
  --force