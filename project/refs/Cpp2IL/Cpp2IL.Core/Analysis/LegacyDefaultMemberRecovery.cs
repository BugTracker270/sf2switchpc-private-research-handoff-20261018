using System;
using System.Collections.Generic;
using System.Linq;
using Cpp2IL.Core.Logging;
using Cpp2IL.Core.Model.Contexts;
using Cpp2IL.Core.Model.CustomAttributes;
using Cpp2IL.Core.Utils;
using LibCpp2IL.NintendoSwitch;

namespace Cpp2IL.Core.Analysis;

/// <summary>Restore only single-attribute native witnesses with a metadata-backed constructor and matching real property.</summary>
public static class LegacyDefaultMemberRecovery
{
    private const string AttributeName = "System.Reflection.DefaultMemberAttribute";

    public static int Restore(ApplicationAnalysisContext app)
    {
        if (app.Binary is not NsoFile || app.MetadataVersion != 24f) return 0;
        var candidates = new List<(TypeAnalysisContext Owner, AnalyzedCustomAttribute Attribute, ulong Helper, string Value)>();
        foreach (var owner in app.AllTypes)
        {
            if (!owner.HasCustomAttributeWithFullName(AttributeName)) continue;
            owner.AnalyzeCustomAttributeData(false);
            if (owner.CustomAttributes is not [{ } attribute] || attribute.IsSuitableForEmission
                || attribute.Constructor.DeclaringType?.FullName != AttributeName
                || attribute.Constructor.Parameters is not [{ ParameterType.FullName: "System.String" }]
                || owner.CaCacheGeneratorAnalysis is not { } generator) continue;
            generator.EnsureRawBytes();
            var witness = LegacyArm64DefaultMemberPattern.Match(generator.RawBytes.ToArray(), generator.UnderlyingPointer, attribute.Constructor.UnderlyingPointer);
            if (witness == null || !app.Binary.TryMapVirtualAddressToRaw(witness.Value.Utf8Wrapper, out var raw)
                || raw > app.Binary.RawLength - 40
                || !LegacyArm64DefaultMemberPattern.IsStringWrapper(app.Binary.GetRawBinaryContent().Slice((int)raw, 40), witness.Value.Utf8Wrapper)) continue;
            var value = ThrowHelperRecovery.ReadCStringAtVirtualAddress(app, witness.Value.CString, 128);
            if (string.IsNullOrEmpty(value) || value.Any(c => c < 0x20 || c > 0x7e)
                || !owner.Properties.Any(p => p.Name == value && (p.Getter?.Parameters.Count > 0 || p.Setter?.Parameters.Count > 1))) continue;
            candidates.Add((owner, attribute, witness.Value.Utf8Wrapper, value));
        }
        var consensus = candidates.GroupBy(c => c.Helper).Where(group => group.Count() >= 3).ToList();
        if (consensus.Count != 1) return 0;
        var recovered = 0;
        foreach (var candidate in consensus[0])
        {
            candidate.Attribute.ConstructorParameters.Add(new CustomAttributePrimitiveParameter(candidate.Value,
                candidate.Attribute, CustomAttributeParameterKind.ConstructorParam, 0));
            recovered++;
            Logger.VerboseNewline($"Recovered DefaultMember argument for {candidate.Owner.FullName} from original cache generator: {candidate.Value}", "CA Restore");
        }
        Logger.InfoNewline($"Recovered {recovered} DefaultMember arguments from strict native generators and a shared string-wrapper witness at 0x{consensus[0].Key:X}. Property names match metadata; no default name guessed.", "CA Restore");
        return recovered;
    }
}
