"""Record a native-witnessed aggregate ABI gap without inventing recovered CIL."""
import hashlib
import json
from pathlib import Path
import re
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
from usb_boundary import destination
ROOT=Path(__file__).resolve().parents[3]

def main():
    source=ROOT/'refs/Cpp2IL/Cpp2IL.Core/Utils/Arm64CallingConventionResolver.cs';text=source.read_text(encoding='utf-8-sig')
    managed=text[text.index('public override IOperand[] ResolveForManaged'):]
    if 'args.Add(new Register(null, IntegerRegisters[integer++]));' not in managed or 'TypeSizes' in managed:
        raise ValueError('Reinspect changed aggregate argument resolver before using this audit')
    metadata=json.loads((ROOT/'analysis/il2cpp/effective-main/script.json').read_text(encoding='utf-8-sig'))
    counts={}
    for type_name,label in [('CodeStage_AntiCheat_ObscuredTypes_ObscuredInt_o','ObscuredInt16'),('CodeStage_AntiCheat_ObscuredTypes_ObscuredLong_o','ObscuredLong32')]:
        returns=[];arguments=[]
        for row in metadata['ScriptMethod']:
            signature=row['Signature'];head,parameters=signature.split('(',1)
            if re.match(r'\s*'+type_name+r'\s+',head):returns.append(row['Address'])
            if re.search(r'\b'+type_name+r'\s+[A-Za-z_]',parameters):arguments.append(row['Address'])
        counts[label]=dict(return_method_records=len(returns),return_distinct_addresses=len(set(returns)),
            by_value_argument_records=len(arguments),by_value_argument_distinct_addresses=len(set(arguments)))
    int_result=json.loads((ROOT/'reports/native-currency-codec.json').read_text())
    long_result=json.loads((ROOT/'reports/native-currency-long.json').read_text())
    report=dict(status='CONFIRMED_SCOPED_AGGREGATE_RECOVERY_GAP',tool_source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
        tool_source=str(source.relative_to(ROOT)),metadata_signature_counts=counts,
        witnesses=[dict(rva='0x794890',operation='ObscuredInt to int',native='Legacy static dummy X0; 16-byte value consumed from X1/X2; MethodInfo unused in this wrapper',
            resolver='One integer register per non-floating managed argument; MethodInfo assigned X2, overlapping the second value word',
            native_text_sha256=int_result['original_text_sha256']['int_to_plain']),
            dict(rva='0xD3D370',operation='CurrencyStruct.set_Count',native='Stores X1 and X2 together at this+0x18',
                resolver='Single integer operand for the 16-byte managed count',native_text_sha256=int_result['original_text_sha256']['currency_set_count']),
            dict(rva='0x7926A0',operation='int to ObscuredInt',native='16-byte result in X0/X1',
                resolver='ReturnRegister exposes X0 only',native_text_sha256=int_result['original_text_sha256']['int_from_plain']),
            dict(rva='0x792BB0',operation='long to ObscuredLong control',native='32-byte indirect result addressed by X8',
                resolver='Hidden result buffer modeled for unboxed sizes greater than 16',native_text_sha256=long_result['original_text_sha256']['long_from_plain'])],
        native_tests=dict(currency_int_checks=int_result['checks'],currency_long_checks=long_result['checks']),
        scope='Confirmed for these original currency shapes. Signature counts identify review candidates, not incorrect-method or reachable-call totals. No aggregate CIL fix, generic/HFA ABI certification or buildable game source claim. Full support must carry all words through entry, SSA, calls, returns, stack copies and CIL emission; advancing a register counter alone is insufficient.')
    destination(ROOT,ROOT/'reports/arm64-currency-abi-gap.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
