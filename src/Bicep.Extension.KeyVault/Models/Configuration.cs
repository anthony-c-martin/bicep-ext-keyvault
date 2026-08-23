using Bicep.Local.Extension.Types.Attributes;

namespace Bicep.Extension.KeyVault;

public class Configuration
{
    [TypeProperty("The URI of the Key Vault, e.g. 'https://myvault.vault.azure.net/'. Individual resources may override this with their own 'vaultUri' property.")]
    public string? VaultUri { get; set; }

    [TypeProperty("The URI of the Managed HSM, e.g. 'https://myhsm.managedhsm.azure.net/'. Individual resources may override this with their own 'managedHsmUri' property.")]
    public string? ManagedHsmUri { get; set; }

    [TypeProperty("Permanently purge objects after deleting them, instead of leaving them in a soft-deleted state. Defaults to false.")]
    public bool? PurgeOnDelete { get; set; }

    [TypeProperty("Recover objects that are in a soft-deleted state instead of failing to create them. Defaults to false.")]
    public bool? RecoverSoftDeleted { get; set; }
}
