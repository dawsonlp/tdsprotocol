// Microsoft's SqlClient reads what Python and Rust wrote in Azure SQL (D-62): each client's Key Vault value, and the
// enclave queries on each client's randomized columns, with attestation "None" as both drivers use. It signs in as
// the campaign's service principal, which may use the vault key. Prints JSON; exits 1 on any mismatch.
using System.Data;
using System.Text.Json;
using Azure.Identity;
using Microsoft.Data.SqlClient;
using Microsoft.Data.SqlClient.AlwaysEncrypted.AzureKeyVaultProvider;

string Env(string name) => Environment.GetEnvironmentVariable(name) ?? throw new InvalidOperationException($"set {name}");
var credential = new ClientSecretCredential(Env("AZURE_TENANT_ID"), Env("AZURE_CLIENT_ID"), Env("AZURE_CLIENT_SECRET"));
SqlConnection.RegisterColumnEncryptionKeyStoreProviders(new Dictionary<string, SqlColumnEncryptionKeyStoreProvider>
{
    [SqlColumnEncryptionAzureKeyVaultProvider.ProviderName] = new SqlColumnEncryptionAzureKeyVaultProvider(credential),
});
var builder = new SqlConnectionStringBuilder
{
    DataSource = $"tcp:{Env("TDS_AZURE_SQL_SERVER")},1433",
    InitialCatalog = Env("TDS_AZURE_SQL_DATABASE"),
    Authentication = SqlAuthenticationMethod.ActiveDirectoryServicePrincipal,
    UserID = Env("AZURE_CLIENT_ID"),
    Password = Env("AZURE_CLIENT_SECRET"),
    ColumnEncryptionSetting = SqlConnectionColumnEncryptionSetting.Enabled,
    AttestationProtocol = SqlConnectionAttestationProtocol.None,
};
using var connection = new SqlConnection(builder.ConnectionString);
connection.Open();

List<string> Read(string sql, SqlParameter? parameter = null)
{
    using var command = new SqlCommand(sql, connection);
    if (parameter is not null) command.Parameters.Add(parameter);
    using var reader = command.ExecuteReader();
    var values = new List<string>();
    while (reader.Read()) values.Add(reader.GetString(0));
    return values;
}

var results = new Dictionary<string, object>();
var ok = true;
foreach (var prefix in new[] { "rust", "python" })
{
    var value = Read($"SELECT v FROM dbo.{prefix}_akv");
    var like = Read($"SELECT name FROM dbo.{prefix}_enclave WHERE name LIKE @p ORDER BY id",
        new SqlParameter("@p", SqlDbType.NVarChar, 50) { Value = "A%" });
    var more = Read($"SELECT name FROM dbo.{prefix}_enclave WHERE salary > @s ORDER BY id",
        new SqlParameter("@s", SqlDbType.Int) { Value = 50000 });
    ok &= value.SequenceEqual(["kept in a vault"]) && like.SequenceEqual(["Ada", "Alan"]) && more.SequenceEqual(["Alan", "Grace"]);
    results[prefix] = new { value, like, more };
}
Console.WriteLine(JsonSerializer.Serialize(new { ok, results }));
return ok ? 0 : 1;
