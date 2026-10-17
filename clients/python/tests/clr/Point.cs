// A user CLR type for the live tests (M7). It is a fixed-size point, serialized in .NET's Native format.
// Build it with build.sh. The tests load the built TdsTestTypes.dll into the test server.
using System;
using System.Data.SqlTypes;
using Microsoft.SqlServer.Server;

[Serializable]
[SqlUserDefinedType(Format.Native, IsByteOrdered = true)]
public struct Point : INullable
{
    private bool present;
    private int x;
    private int y;

    public bool IsNull { get { return !present; } }
    public static Point Null { get { return new Point(); } }
    public int X { get { return x; } }
    public int Y { get { return y; } }

    public override string ToString() { return IsNull ? "NULL" : x + "," + y; }

    public static Point Parse(SqlString s)
    {
        if (s.IsNull) return Null;
        string[] parts = s.Value.Split(',');
        Point p = new Point();
        p.present = true;
        p.x = int.Parse(parts[0]);
        p.y = int.Parse(parts[1]);
        return p;
    }
}
