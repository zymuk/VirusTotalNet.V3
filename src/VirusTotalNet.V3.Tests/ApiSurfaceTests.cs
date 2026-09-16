using System.Reflection;
using System.Runtime.Loader;

namespace VirusTotalNet.V3.Tests;

/// <summary>
/// Condition #4 verification — API-surface diff of the <c>net8.0</c> and <c>netstandard2.0</c> builds.
/// The documented contract: only <c>TraverseAsync</c> (returns <see cref="IAsyncEnumerable{T}"/>) and the
/// <c>GetAsync&lt;T&gt;(string, JsonTypeInfo&lt;VtResponse&lt;T&gt;&gt;, ct)</c> overload may be
/// net8.0-only (<c>#if NET8_0_OR_GREATER</c>); every other public member must exist on both TFMs.
/// </summary>
public class ApiSurfaceTests
{
    [Fact]
    public void Net8vsNetStandard20_SurfaceDiff_SameExceptDocumentedNet8OnlyMembers()
    {
        var net8Api = ExtractPublicApi(typeof(VirusTotal).Assembly);
        var ns20Api = ExtractPublicApi(LoadNetStandard20Assembly());

        var onlyNet8 = net8Api.Except(ns20Api).OrderBy(s => s, StringComparer.Ordinal).ToArray();
        var onlyNs20 = ns20Api.Except(net8Api).OrderBy(s => s, StringComparer.Ordinal).ToArray();

        Assert.Empty(onlyNs20);

        var unexpected = onlyNet8
            .Where(s => !s.Contains("IAsyncEnumerable") && !s.Contains("JsonTypeInfo"))
            .ToArray();
        Assert.True(
            unexpected.Length == 0,
            "Unexpected net8.0-only public members (must be covered by IAsyncEnumerable/JsonTypeInfo):\n"
            + string.Join('\n', unexpected));
    }

    [Fact]
    public void Net8vsNetStandard20_SurfaceDiff_HasExactlyTheDocumentedNet8OnlyMembers()
    {
        var net8Api = ExtractPublicApi(typeof(VirusTotal).Assembly);
        var ns20Api = ExtractPublicApi(LoadNetStandard20Assembly());

        var onlyNet8 = net8Api.Except(ns20Api).OrderBy(SignatureId, StringComparer.Ordinal).ToArray();
        var onlyNs20 = ns20Api.Except(net8Api).OrderBy(s => s, StringComparer.Ordinal).ToArray();

        Assert.Empty(onlyNs20);

        Assert.Equal(
            new[]
            {
                "VirusTotalNet.V3.Core.VtClient::method::GetAsync",
                "VirusTotalNet.V3.Relationships.IRelationshipsClient::method::TraverseAsync",
                "VirusTotalNet.V3.Relationships.RelationshipsClient::method::TraverseAsync",
                "VirusTotalNet.V3.VirusTotal::method::TraverseRelatedAsync",
            },
            onlyNet8.Select(SignatureId).Distinct(StringComparer.Ordinal).OrderBy(s => s, StringComparer.Ordinal).ToArray());
    }

    private static string SignatureId(string signature)
    {
        string head = signature.Split('(')[0];
        int generic = head.LastIndexOf('<');
        return generic > 0 ? head[..generic] : head;
    }

    private static Assembly LoadNetStandard20Assembly()
    {
        string path = NetStandard20AssemblyPath();
        Assert.True(File.Exists(path), $"netstandard2.0 build not found at {path} — build the solution first.");

        var alc = new AssemblyLoadContext("vt-ns20-surface", isCollectible: true);
        alc.Resolving += (_, name) =>
        {
            try
            {
                return Assembly.Load(new AssemblyName(name.Name!));
            }
            catch
            {
                return null;
            }
        };

        try
        {
            return alc.LoadFromAssemblyPath(path);
        }
        catch
        {
            alc.Unload();
            throw;
        }
    }

    private static string NetStandard20AssemblyPath()
    {
        string config = Path.GetFileName(Path.GetDirectoryName(Path.GetDirectoryName(AppContext.BaseDirectory)))!;

        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "src", "VirusTotalNet.V3.sln")))
            dir = dir.Parent;

        Assert.True(dir is not null, "Could not locate repo root from the test output directory.");

        return Path.Combine(dir.FullName, "src", "VirusTotalNet.V3", "bin", config, "netstandard2.0", "VirusTotalNet.V3.dll");
    }

    private static HashSet<string> ExtractPublicApi(Assembly asm)
    {
        Type[] types;
        try
        {
            types = asm.GetTypes();
        }
        catch (ReflectionTypeLoadException ex)
        {
            types = ex.Types.Where(t => t is not null).Cast<Type>().ToArray();
        }

        var signatures = new HashSet<string>(StringComparer.Ordinal);

        foreach (var type in types)
        {
            if (!type.IsVisible)
                continue;

            string typeKey = type.FullName!;

            foreach (var ctor in type.GetConstructors(BindingFlags.Public | BindingFlags.Instance))
            {
                string args = string.Join(",", ctor.GetParameters().Select(p => TypeKey(p.ParameterType)));
                signatures.Add($"{typeKey}::ctor({args})");
            }

            foreach (var prop in type.GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly))
                signatures.Add($"{typeKey}::prop::{prop.Name}:{TypeKey(prop.PropertyType)}");

            foreach (var evt in type.GetEvents(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly))
                signatures.Add($"{typeKey}::event::{evt.Name}");

            foreach (var method in type.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly))
            {
                if (method.IsSpecialName)
                    continue;

                string args = string.Join(",", method.GetParameters().Select(p => TypeKey(p.ParameterType)));
                string key = method.IsGenericMethodDefinition
                    ? $"{typeKey}::method::{method.Name}<{method.GetGenericArguments().Length}>({args}):{TypeKey(method.ReturnType)}"
                    : $"{typeKey}::method::{method.Name}({args}):{TypeKey(method.ReturnType)}";
                signatures.Add(key);
            }

            foreach (var field in type.GetFields(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly))
            {
                if (field.IsSpecialName)
                    continue;

                signatures.Add($"{typeKey}::field::{field.Name}:{TypeKey(field.FieldType)}");
            }
        }

        return signatures;
    }

    private static string TypeKey(Type type)
    {
        string key = type.FullName ?? type.Name;
        return key.Replace('+', '.');
    }
}