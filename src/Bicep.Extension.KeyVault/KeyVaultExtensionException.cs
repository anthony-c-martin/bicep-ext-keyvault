namespace Bicep.Extension.KeyVault;

/// <summary>
/// An error that should be surfaced to the user as a structured, actionable failure rather than a
/// generic RPC exception. <see cref="Handlers.KeyVaultResourceHandler{TProperties, TIdentifiers}"/>
/// translates these into the extension host's error contract.
/// </summary>
public sealed class KeyVaultExtensionException : Exception
{
    public KeyVaultExtensionException(string code, string message, string? target = null)
        : base(message)
    {
        Code = code;
        Target = target;
    }

    public string Code { get; }

    public string? Target { get; }
}
