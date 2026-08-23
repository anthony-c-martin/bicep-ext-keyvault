using Azure;
using Azure.Security.KeyVault.Administration;

namespace Bicep.Extension.KeyVault.Handlers;

public class ManagedHsmRoleDefinitionHandler : KeyVaultResourceHandler<ManagedHsmRoleDefinition, ManagedHsmRoleDefinitionIdentifiers>
{
    protected override Uri ResolveEndpoint(ManagedHsmRoleDefinitionIdentifiers identifiers, Configuration configuration)
    {
        var endpoint = ResolveEndpoint(identifiers.ManagedHsmUri, configuration.ManagedHsmUri, nameof(ManagedHsmRoleDefinition.ManagedHsmUri), nameof(Configuration.ManagedHsmUri));
        identifiers.ManagedHsmUri = endpoint.AbsoluteUri;

        return endpoint;
    }

    protected override async Task<ResourceResponse> CreateOrUpdate(ResourceRequest request, CancellationToken cancellationToken)
    {
        var properties = request.Properties;
        var hsmUri = ResolveEndpoint(properties, request.Config);
        var client = KeyVaultClients.AccessControl(hsmUri);

        var scope = new KeyVaultRoleScope(properties.Scope);
        var options = new CreateOrUpdateRoleDefinitionOptions(scope, ParseGuid(properties.Name, nameof(ManagedHsmRoleDefinition.Name)))
        {
            RoleName = properties.RoleName,
            Description = properties.Description,
        };

        foreach (var permission in properties.Permissions ?? [])
        {
            var value = new KeyVaultPermission();
            AddRange(permission.Actions, value.Actions);
            AddRange(permission.NotActions, value.NotActions);
            AddRange(permission.DataActions, value.DataActions.Add, action => new KeyVaultDataAction(action));
            AddRange(permission.NotDataActions, value.NotDataActions.Add, action => new KeyVaultDataAction(action));

            options.Permissions.Add(value);
        }

        foreach (var assignableScope in properties.AssignableScopes ?? [])
        {
            options.AssignableScopes.Add(new KeyVaultRoleScope(assignableScope));
        }

        var definition = await client.CreateOrUpdateRoleDefinitionAsync(options, cancellationToken);

        ApplyOutputs(properties, definition.Value);

        return GetResponse(request);
    }

    protected override async Task<ResourceResponse> Get(ReferenceRequest request, CancellationToken cancellationToken)
    {
        var identifiers = request.Identifiers;
        var hsmUri = ResolveEndpoint(identifiers, request.Config);
        var client = KeyVaultClients.AccessControl(hsmUri);

        var scope = new KeyVaultRoleScope(identifiers.Scope);
        var name = ParseGuid(identifiers.Name, nameof(ManagedHsmRoleDefinition.Name));

        KeyVaultRoleDefinition definition;
        try
        {
            definition = await client.GetRoleDefinitionAsync(scope, name, cancellationToken);
        }
        catch (RequestFailedException exception) when (IsNotFound(exception))
        {
            throw new KeyVaultExtensionException("ResourceNotFound", $"The role definition '{identifiers.Name}' was not found at scope '{identifiers.Scope}' in Managed HSM '{hsmUri}'.", nameof(ManagedHsmRoleDefinition.Name));
        }

        var properties = new ManagedHsmRoleDefinition
        {
            ManagedHsmUri = identifiers.ManagedHsmUri,
            Scope = identifiers.Scope,
            Name = identifiers.Name,
            RoleName = definition.RoleName,
            Description = definition.Description,
            AssignableScopes = Conversions.ToArray(definition.AssignableScopes?.Select(value => value.ToString())),
            Permissions = definition.Permissions?.Select(permission => new ManagedHsmPermission
            {
                Actions = Conversions.ToArray(permission.Actions),
                NotActions = Conversions.ToArray(permission.NotActions),
                DataActions = Conversions.ToArray(permission.DataActions?.Select(action => action.ToString())),
                NotDataActions = Conversions.ToArray(permission.NotDataActions?.Select(action => action.ToString())),
            }).ToArray(),
        };

        ApplyOutputs(properties, definition);

        return GetResponse(request, properties);
    }

    protected override async Task<ResourceResponse> Delete(ReferenceRequest request, CancellationToken cancellationToken)
    {
        var identifiers = request.Identifiers;
        var hsmUri = ResolveEndpoint(identifiers, request.Config);
        var client = KeyVaultClients.AccessControl(hsmUri);

        try
        {
            await client.DeleteRoleDefinitionAsync(
                new KeyVaultRoleScope(identifiers.Scope),
                ParseGuid(identifiers.Name, nameof(ManagedHsmRoleDefinition.Name)),
                cancellationToken);
        }
        catch (RequestFailedException exception) when (IsNotFound(exception))
        {
            // Already gone; deletion is idempotent.
        }

        return GetResponse(request, null);
    }

    protected override ManagedHsmRoleDefinitionIdentifiers GetIdentifiers(ManagedHsmRoleDefinition properties)
        => new()
        {
            ManagedHsmUri = properties.ManagedHsmUri,
            Scope = properties.Scope,
            Name = properties.Name,
        };

    private static void AddRange<T>(IEnumerable<T>? source, ICollection<T> destination)
    {
        foreach (var value in source ?? [])
        {
            destination.Add(value);
        }
    }

    private static void AddRange<TIn, TOut>(IEnumerable<TIn>? source, Action<TOut> add, Func<TIn, TOut> transform)
    {
        foreach (var value in source ?? [])
        {
            add(transform(value));
        }
    }

    private static void ApplyOutputs(ManagedHsmRoleDefinition properties, KeyVaultRoleDefinition definition)
    {
        properties.Id = definition.Id;
        properties.RoleType = definition.RoleType?.ToString();
    }
}

public class ManagedHsmRoleAssignmentHandler : KeyVaultResourceHandler<ManagedHsmRoleAssignment, ManagedHsmRoleAssignmentIdentifiers>
{
    protected override Uri ResolveEndpoint(ManagedHsmRoleAssignmentIdentifiers identifiers, Configuration configuration)
    {
        var endpoint = ResolveEndpoint(identifiers.ManagedHsmUri, configuration.ManagedHsmUri, nameof(ManagedHsmRoleAssignment.ManagedHsmUri), nameof(Configuration.ManagedHsmUri));
        identifiers.ManagedHsmUri = endpoint.AbsoluteUri;

        return endpoint;
    }

    protected override async Task<ResourceResponse> CreateOrUpdate(ResourceRequest request, CancellationToken cancellationToken)
    {
        var properties = request.Properties;
        var hsmUri = ResolveEndpoint(properties, request.Config);
        var client = KeyVaultClients.AccessControl(hsmUri);

        var scope = new KeyVaultRoleScope(properties.Scope);
        var name = ParseGuid(properties.Name, nameof(ManagedHsmRoleAssignment.Name));

        // Role assignments are immutable, so creating one that already exists conflicts. Treat an
        // existing, matching assignment as success and a differing one as an error the user must
        // resolve, since silently replacing an access grant would be surprising.
        var existing = await TryGetAssignmentAsync(client, scope, properties.Name, cancellationToken);
        if (existing is not null)
        {
            if (!string.Equals(existing.Properties.PrincipalId, properties.PrincipalId, StringComparison.OrdinalIgnoreCase) ||
                !EndsWithRoleDefinition(existing.Properties.RoleDefinitionId, properties.RoleDefinitionId))
            {
                throw new KeyVaultExtensionException(
                    "ImmutableResource",
                    $"The role assignment '{properties.Name}' already exists at scope '{properties.Scope}' with a different principal or role definition. Role assignments are immutable; delete it before recreating it.",
                    nameof(ManagedHsmRoleAssignment.Name));
            }

            properties.Id = existing.Id;

            return GetResponse(request);
        }

        var assignment = await client.CreateRoleAssignmentAsync(scope, properties.RoleDefinitionId, properties.PrincipalId, name, cancellationToken);
        properties.Id = assignment.Value.Id;

        return GetResponse(request);
    }

    protected override async Task<ResourceResponse> Get(ReferenceRequest request, CancellationToken cancellationToken)
    {
        var identifiers = request.Identifiers;
        var hsmUri = ResolveEndpoint(identifiers, request.Config);
        var client = KeyVaultClients.AccessControl(hsmUri);

        var scope = new KeyVaultRoleScope(identifiers.Scope);
        var assignment = await TryGetAssignmentAsync(client, scope, identifiers.Name, cancellationToken)
            ?? throw new KeyVaultExtensionException("ResourceNotFound", $"The role assignment '{identifiers.Name}' was not found at scope '{identifiers.Scope}' in Managed HSM '{hsmUri}'.", nameof(ManagedHsmRoleAssignment.Name));

        var properties = new ManagedHsmRoleAssignment
        {
            ManagedHsmUri = identifiers.ManagedHsmUri,
            Scope = identifiers.Scope,
            Name = identifiers.Name,
            PrincipalId = assignment.Properties.PrincipalId,
            RoleDefinitionId = assignment.Properties.RoleDefinitionId,
            Id = assignment.Id,
        };

        return GetResponse(request, properties);
    }

    protected override async Task<ResourceResponse> Delete(ReferenceRequest request, CancellationToken cancellationToken)
    {
        var identifiers = request.Identifiers;
        var hsmUri = ResolveEndpoint(identifiers, request.Config);
        var client = KeyVaultClients.AccessControl(hsmUri);

        try
        {
            await client.DeleteRoleAssignmentAsync(new KeyVaultRoleScope(identifiers.Scope), identifiers.Name, cancellationToken);
        }
        catch (RequestFailedException exception) when (IsNotFound(exception))
        {
            // Already gone; deletion is idempotent.
        }

        return GetResponse(request, null);
    }

    protected override ManagedHsmRoleAssignmentIdentifiers GetIdentifiers(ManagedHsmRoleAssignment properties)
        => new()
        {
            ManagedHsmUri = properties.ManagedHsmUri,
            Scope = properties.Scope,
            Name = properties.Name,
        };

    private static async Task<KeyVaultRoleAssignment?> TryGetAssignmentAsync(
        KeyVaultAccessControlClient client,
        KeyVaultRoleScope scope,
        string name,
        CancellationToken cancellationToken)
    {
        try
        {
            return await client.GetRoleAssignmentAsync(scope, name, cancellationToken);
        }
        catch (RequestFailedException exception) when (exception.Status == 404)
        {
            return null;
        }
    }

    /// <summary>
    /// Role definitions may be referenced either by their bare GUID or by a fully qualified path,
    /// so compare on the trailing segment.
    /// </summary>
    private static bool EndsWithRoleDefinition(string? actual, string desired)
    {
        if (actual is null)
        {
            return false;
        }

        var actualName = actual.Split('/')[^1];
        var desiredName = desired.Split('/')[^1];

        return string.Equals(actualName, desiredName, StringComparison.OrdinalIgnoreCase);
    }
}
