#!/bin/bash
set -e

root="$(dirname ${BASH_SOURCE[0]})/.."

dotnet run --project "$root/src/Bicep.Types.KeyVault/Bicep.Types.KeyVault.csproj" -- --outdir "$root/types"