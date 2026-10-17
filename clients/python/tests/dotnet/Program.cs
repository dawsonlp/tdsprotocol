// Always Encrypted, pass 2 (D-61). Microsoft's SqlClient is tested against what the driver wrote, and the driver
// against what SqlClient writes. tests/test_encryption_dotnet_live.py runs this program through run.sh, and the cases
// arrive as JSON on stdin.
//
// Each case is one SQL type. Its tables are the driver's tables, one for each prefix in the input's "read" list
// (dbo.py_<table> written by INSERT, dbo.pyb_<table> written by bulk load), and dbo.net_<table>, which starts empty.
// Each table has the columns id, d (deterministic) and r (randomized). For each case, the program does these steps:
//   read     every row of each of the driver's tables, in id order
//   lookup   each value, by WHERE d = @d in each of the driver's tables, giving the ids found
//   write    each value, and NULL, into dbo.net_<table>
// Values travel as exact text. Floats travel as their bits, times as 100 ns ticks, binary as hex, and text as the hex
// of its UTF-16 code units, so that unpaired surrogates also cross (JSON can't carry them). See Canon and Value.
using System.Data;
using System.Data.SqlTypes;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Data.SqlClient;

var spec = JsonNode.Parse(Console.In.ReadToEnd())!;
SqlConnection.RegisterColumnEncryptionKeyStoreProviders(
    new Dictionary<string, SqlColumnEncryptionKeyStoreProvider> { [LocalKeys.Name] = new LocalKeys("/keys") });
var connectionString = new SqlConnectionStringBuilder
{
    DataSource = "localhost,1433", UserID = "sa", Password = Environment.GetEnvironmentVariable("TDS_PASSWORD"),
    InitialCatalog = (string)spec["database"]!, Encrypt = SqlConnectionEncryptOption.Mandatory,
    ColumnEncryptionSetting = SqlConnectionColumnEncryptionSetting.Enabled,
}.ConnectionString;
using var connection = new SqlConnection(connectionString);
connection.Open();

var prefixes = spec["read"]!.AsArray().Select(p => (string)p!).ToList();
var results = new JsonArray();
foreach (var c in spec["cases"]!.AsArray())
{
    string table = (string)c!["table"]!, kind = (string)c["kind"]!;
    var values = c["values"]!.AsArray().Select(v => (string?)v).ToList();
    var result = new JsonObject();
    try
    {
        var read = new JsonObject();
        var lookup = new JsonObject();
        foreach (var prefix in prefixes)
        {
            var rows = new JsonArray();
            using (var select = new SqlCommand($"SELECT d, r FROM dbo.{prefix}_{table} ORDER BY id", connection))
            using (var reader = select.ExecuteReader())
                while (reader.Read())
                    rows.Add(new JsonArray(Canon(reader, 0, kind), Canon(reader, 1, kind)));
            read[prefix] = rows;

            var found = new JsonArray();
            foreach (var value in values)
            {
                using var find = new SqlCommand($"SELECT id FROM dbo.{prefix}_{table} WHERE d = @d ORDER BY id", connection);
                find.Parameters.Add(Parameter("@d", c, value));
                var ids = new JsonArray();
                using var reader = find.ExecuteReader();
                while (reader.Read()) ids.Add(reader.GetInt32(0));
                found.Add(ids);
            }
            lookup[prefix] = found;
        }
        result["read"] = read;
        result["lookup"] = lookup;

        for (int id = 0; id <= values.Count; id++)
        {
            string? value = id < values.Count ? values[id] : null;
            using var insert = new SqlCommand($"INSERT dbo.net_{table} (id, d, r) VALUES (@id, @d, @r)", connection);
            insert.Parameters.Add(new SqlParameter("@id", SqlDbType.Int) { Value = id });
            insert.Parameters.Add(Parameter("@d", c, value));
            insert.Parameters.Add(Parameter("@r", c, value));
            insert.ExecuteNonQuery();
        }
    }
    catch (Exception e)
    {
        result["error"] = $"{e.GetType().Name}: {e.Message}";
    }
    results.Add(result);
}
Console.WriteLine(new JsonObject { ["cases"] = results }.ToJsonString());

static SqlParameter Parameter(string name, JsonNode c, string? text)
{
    string kind = (string)c["kind"]!;
    var p = new SqlParameter(name, kind switch
    {
        "tinyint" => SqlDbType.TinyInt, "smallint" => SqlDbType.SmallInt, "int" => SqlDbType.Int, "bigint" => SqlDbType.BigInt,
        "bit" => SqlDbType.Bit, "real" => SqlDbType.Real, "float" => SqlDbType.Float,
        "decimal" or "numeric" => SqlDbType.Decimal, "money" => SqlDbType.Money, "smallmoney" => SqlDbType.SmallMoney,
        "date" => SqlDbType.Date, "time" => SqlDbType.Time, "datetime2" => SqlDbType.DateTime2,
        "datetimeoffset" => SqlDbType.DateTimeOffset, "datetime" => SqlDbType.DateTime,
        "smalldatetime" => SqlDbType.SmallDateTime, "uniqueidentifier" => SqlDbType.UniqueIdentifier,
        "char" => SqlDbType.Char, "varchar" => SqlDbType.VarChar, "nchar" => SqlDbType.NChar, "nvarchar" => SqlDbType.NVarChar,
        "binary" => SqlDbType.Binary, "varbinary" => SqlDbType.VarBinary,
        _ => throw new ArgumentException(kind),
    });
    if (c["size"] is JsonNode size) p.Size = (int)size;
    if (c["precision"] is JsonNode precision) p.Precision = (byte)(int)precision;
    if (c["scale"] is JsonNode scale) p.Scale = (byte)(int)scale;
    p.Value = text is null ? DBNull.Value : Value(kind, text);
    return p;
}

static object Value(string kind, string t)
{
    var inv = CultureInfo.InvariantCulture;
    string[] part = t.Split('|');
    return kind switch
    {
        "tinyint" => byte.Parse(t, inv), "smallint" => short.Parse(t, inv), "int" => int.Parse(t, inv),
        "bigint" => long.Parse(t, inv), "bit" => t == "1",
        "real" => BitConverter.UInt32BitsToSingle(uint.Parse(t, NumberStyles.HexNumber)),
        "float" => BitConverter.UInt64BitsToDouble(ulong.Parse(t, NumberStyles.HexNumber)),
        "decimal" or "numeric" => SqlDecimal.Parse(t),
        "money" or "smallmoney" => decimal.Parse(t, inv),
        "date" => DateTime.ParseExact(t, "yyyy-MM-dd", inv),
        "time" => new TimeSpan(long.Parse(t, inv)),
        "datetime2" => DateTime.ParseExact(part[0], "yyyy-MM-dd", inv).AddTicks(long.Parse(part[1], inv)),
        "datetimeoffset" => new DateTimeOffset(DateTime.ParseExact(part[0], "yyyy-MM-dd", inv).AddTicks(long.Parse(part[1], inv)),
                                               TimeSpan.Zero).ToOffset(TimeSpan.FromMinutes(int.Parse(part[2], inv))),
        "datetime" => new SqlDateTime(int.Parse(part[0], inv), int.Parse(part[1], inv)),
        "smalldatetime" => DateTime.ParseExact(t, "yyyy-MM-ddTHH:mm", inv),
        "uniqueidentifier" => Guid.Parse(t),
        "char" or "varchar" or "nchar" or "nvarchar" => new string(MemoryMarshal.Cast<byte, char>(Convert.FromHexString(t))),
        "binary" or "varbinary" => Convert.FromHexString(t),
        _ => throw new ArgumentException(kind),
    };
}

static string? Canon(SqlDataReader r, int i, string kind)
{
    if (r.IsDBNull(i)) return null;
    var inv = CultureInfo.InvariantCulture;
    return kind switch
    {
        "tinyint" => r.GetByte(i).ToString(inv), "smallint" => r.GetInt16(i).ToString(inv),
        "int" => r.GetInt32(i).ToString(inv), "bigint" => r.GetInt64(i).ToString(inv),
        "bit" => r.GetBoolean(i) ? "1" : "0",
        "real" => BitConverter.SingleToUInt32Bits(r.GetFloat(i)).ToString("x8"),
        "float" => BitConverter.DoubleToUInt64Bits(r.GetDouble(i)).ToString("x16"),
        "decimal" or "numeric" => r.GetSqlDecimal(i).ToString(),
        "money" or "smallmoney" => r.GetDecimal(i).ToString(inv),
        "date" => r.GetDateTime(i).ToString("yyyy-MM-dd", inv),
        "time" => r.GetTimeSpan(i).Ticks.ToString(inv),
        "datetime2" => $"{r.GetDateTime(i).ToString("yyyy-MM-dd", inv)}|{r.GetDateTime(i).TimeOfDay.Ticks}",
        "datetimeoffset" => $"{r.GetDateTimeOffset(i).UtcDateTime.ToString("yyyy-MM-dd", inv)}|{r.GetDateTimeOffset(i).UtcDateTime.TimeOfDay.Ticks}|{(int)r.GetDateTimeOffset(i).Offset.TotalMinutes}",
        "datetime" => $"{r.GetSqlDateTime(i).DayTicks}|{r.GetSqlDateTime(i).TimeTicks}",
        "smalldatetime" => r.GetDateTime(i).ToString("yyyy-MM-ddTHH:mm", inv),
        "uniqueidentifier" => r.GetGuid(i).ToString(),
        "char" or "varchar" or "nchar" or "nvarchar" => Convert.ToHexStringLower(MemoryMarshal.AsBytes(r.GetString(i).AsSpan())),
        "binary" or "varbinary" => Convert.ToHexStringLower(r.GetSqlBinary(i).Value),
        _ => throw new ArgumentException(kind),
    };
}
