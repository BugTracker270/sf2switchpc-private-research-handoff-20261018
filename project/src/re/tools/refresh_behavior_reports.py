"""Write scoped research findings from local native/serialized evidence."""
import collections
import csv
import datetime
import json
from pathlib import Path
import sqlite3
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
from usb_boundary import destination
ROOT=Path(__file__).resolve().parents[3]

def read(path):return json.loads((ROOT/path).read_text(encoding='utf-8-sig'))
def write(path,value):destination(ROOT,ROOT/path).write_text(value,encoding='utf-8')
def csv_out(path,rows):
    with destination(ROOT,ROOT/path).open('w',encoding='utf-8',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)

def find_calls(value):
    if isinstance(value,dict):
        if value.get('m_MethodName')=='LoadGameAtSaveSlot':yield value['m_Arguments']['m_IntArgument']
        for child in value.values():yield from find_calls(child)
    elif isinstance(value,list):
        for child in value:yield from find_calls(child)

def find_method_calls(value,method):
    if isinstance(value,dict):
        if value.get('m_MethodName')==method:yield value
        for child in value.values():yield from find_method_calls(child,method)
    elif isinstance(value,list):
        for child in value:yield from find_method_calls(child,method)

def main():
    now=datetime.datetime.now(datetime.timezone.utc).isoformat()
    source=read('analysis/assets/source-manifest-summary.json');graph=read('analysis/assets/asset-graph-summary.json')
    db=sqlite3.connect(ROOT/'analysis/assets/asset-graph.sqlite')
    slot_objects={(f,i) for f,i in db.execute('SELECT source_file,path_id FROM components WHERE script_type=?',('Nekki.SF2.GUI.GeneralMenu.MenuItemStory',))}
    slots=[]
    for row in map(json.loads,(ROOT/'analysis/assets/typed-components/sequential-validation.jsonl').open(encoding='utf-8')):
        if (row['source_file'],row['path_id']) in slot_objects:
            slots.append(dict(source_file=row['source_file'],path_id=row['path_id'],slots=sorted(set(find_calls(row.get('data',{}))))))
    indices=sorted({i for r in slots for i in r['slots']})
    if indices!=[0,1,2,3]:raise ValueError('Four serialized save slot bindings were not established')
    write('analysis/assets/save-slot-bindings.json',json.dumps(dict(indices=indices,components=slots,source='Sequential metadata-assisted decode, raw original component/script identities independently matched'),indent=2)+'\n')
    script_types={(f,i):s for f,i,s in db.execute('SELECT source_file,path_id,script_type FROM components')}
    pvp_bindings=[]
    for row in map(json.loads,(ROOT/'analysis/assets/typed-components/sequential-validation.jsonl').open(encoding='utf-8')):
        for call in find_method_calls(row.get('data',{}),'ShowPvp'):
            target=call['m_Target']
            if target['m_FileID']!=0:raise ValueError('Resolve external menu callback before reporting')
            pvp_bindings.append(dict(source_file=row['source_file'],path_id=row['path_id'],
                source_type=script_types.get((row['source_file'],row['path_id'])),call=call,
                target_type=script_types.get((row['source_file'],target['m_PathID']))))
    if len(pvp_bindings)!=1 or not pvp_bindings[0]['target_type'].endswith('.GeneralMenuScene'):
        raise ValueError('Switch Sparring entry callback was not established')
    write('analysis/assets/pvp-entry-bindings.json',json.dumps(dict(method='ShowPvp',bindings=pvp_bindings),indent=2)+'\n')
    screen_references=db.execute('SELECT COUNT(*) FROM edges WHERE resolved_file=? AND target_id=?',('resources.assets',15328)).fetchone()[0]
    db.close()
    write('reports/combat-timing.md',f'''# Combat clock and animation evidence

Updated {now}. Scope: static binary/data analysis; no game timing or FPS was measured.

- ApplicationController.Awake, RVA `0xC79BC0`, calls UnityEngine.Application.set_targetFrameRate (`0x1217700`) with **60** (`W1=0x3C`). This is a request, not observed frame presentation.
- Original TimeManager fixed step is approximately `1/60` seconds. Internal settings also contain FrameRateValue=60. The metadata exposes no managed fixedDeltaTime setter in this build; native engine scheduling remains a separate concern.
- FightScene.FixedUpdate, `0xE57190`, is a 20-byte null check and tail call to Fight.Draw (`0xC9DD50`). Ghidra's pseudocode may expand that tail call. The frame loop lives in Draw: it checks GameUtils.IsReduceFPS, runs the fight step once or twice, increments the fight frame counter and conditionally calls RenderFight/RenderCamera. Native data pointer `0x397AD38` resolves to type-info slot `0x3B37410`; the flag is at static offset `0x1F8`. Exact runtime activation of the compensation path is unmeasured.
- ModelContainer.FixedUpdate (`0xEA8610`) and Render (`0xEA6D70`) update custom model state. Methods named Render include simulation work; their names do not justify moving them wholesale into a 120-Hz presentation loop.
- ModelPhysics.TimeStep (`0xE99140`) calls a gravity-producing function at `0xE99520`, then ModelNode.TimeStep (`0xFEBD80`). ARM64 S0 carries the float gravity argument. Early pseudocode omitted it before callee signatures were applied; raw disassembly retains the evidence.
- ModelNode.TimeStep uses current/previous positions, attenuation and a per-step vertical gravity increment. It does not accept elapsed seconds. Changing the number of these calls changes motion and combat speed.
- SystemProperties.SetFrameRate (`0xAEF40`) is a single RET in the supplied build. Reusing a mobile implementation of this method would introduce behavior absent from Switch code.
- Raw damage getter/setter at `0xF968C0` / `0xF968D0` are independently validated float loads/stores at offset `0x1C`.

Custom animation files contain frame-by-frame point positions. All 559 parsed files pass complete bounds, node-count, finite-float and trailing-byte checks; all 910 explicit move-file references resolve. The catalog includes 932 moves, 114 templates and 22 triggers. Twenty-two moves lack explicit filenames and require template/default resolution rather than invented animation data.

Future presentation work must retain original simulation ticks and hit/attack intervals, sample previous/current visual state between ticks, and test hit timing, recovery, projectiles, camera and input latency against the original. No interpolation or Windows implementation is performed in this phase.

Evidence: analysis/nso/behavior-samples; analysis/nso/corpus.sqlite; analysis/assets/content-v2; reports/native-mapping-tests.json. Full combat semantics, collision ordering, all damage formulas and runtime replay equivalence remain IN_PROGRESS.
''')
    save_gate=read('reports/native-save-gate-execution.json')
    write('reports/save-research.md',f'''# Save and profile evidence

Updated {now}. The original game and real saves have not been executed or modified.

Four MenuItemStory components in level7 bind LoadGameAtSaveSlot to indices **0, 1, 2, 3**. Exact original component path IDs and decoded bindings are in analysis/assets/save-slot-bindings.json. A sequential reset/reload restored one initial empty decode without editing the input.

Switch hash-check gate: GameSettings static initializer starts the flag at true, but InitHashChecking (`0xE1B1C0`) unconditionally clears static byte 9. GameLoader.PreloadHacks (`0xF3AE10`) calls it; AntichitingModule.Update (`0xE233E0`) invokes that preload once, and GameLoaderScene.Start constructs the module. The original getter, disabled CheckFileHash and UpdateFileHash(file/document)/DeleteFileHash/CopyFileHash paths execute against synthetic initialized metadata storage: {save_gate['passed']} checks pass, with null inputs and no string/XML/hash/filesystem callees or real saves opened. See reports/native-save-gate-execution.json. This establishes the initializer/disabled paths; complete bootstrap ordering and any later flag writes remain a reachability audit. Android signing-certificate behavior is not imposed on Switch saves.

GeneralMenuScene.LoadGameAtSaveSlot (`0xE6D5A0`) constructs a coroutine carrying the requested slot; its iterator is at `0xE6F310`. ListSF.DeleteSaveSlot (`0xD25B50`) and SomeSaveSlotIsNotEmpty (`0xD28C00`) operate on XML-backed slot data. These functions have native exports, but complete save schema and corruption recovery are not yet certified.

Native save paths are **data:/userdata/users.xml** and **data:/userdata/users_backup.xml**. SF2Paths.Init (`0xE22E30`) assigns CurrentStorage=data:; get_StorageUserData (`0xE1E2C0`) adds /userdata; ListSF path getters format the primary/backup filenames. These are original Switch mount paths, not future Windows destinations. The shipped default document has Root/CurrentUser, Root/Warriors and Root/Versions. Slot-specific Warrior records carry SaveSlot. CurrentUser carries shared sound/music settings and LastSaveSlot. Default-document identities and native string-slot validation are in reports/save-schema-research.json; the default is not a complete schema of later game state.

GetWarriorAtSlot (`0xD26760`) traverses Root/Warriors children and returns the first SaveSlot match using integer conversion with fallback zero. DeleteSaveSlot removes the matching XML node, sets the active slot to -1 if deleting it, then requests a forced roster save. An absent match logs an error. It does not delete a separate per-slot file. SomeSaveSlotIsNotEmpty looks for the persisted StoryTutorialWelcome quest node; it is more specific than merely finding a Warrior element.

After its delay, the menu load coroutine sets GameMode=1. If the requested slot is already active and has a Warrior record, it starts the session directly; otherwise it opens SaveSlotWarning with OK/CANCEL and a callback. The callback starts OnChangeSlotConfirm. Its MoveNext (`0xE6F780`) yields once, unboxes the dialog result and, for result 1, updates ListSF.SaveSlot and MainSettings.SaveSlot before calling GoToModule(0, ..., false). Other results restore menu controls. These are native control-flow traces; no slot-switch gameplay test occurred.

FilesUtil.Initialize (`0xEBAE0`) obtains DeviceUniqueID.uid_switch and passes it to nn.fs.SaveData.Mount with the mount name data. This supplies the selected Switch user boundary for the shared slot document. Account selection, mount errors and full shutdown lifecycle still require validation.

ParseRoster (`0xD109F0`) opens users.xml through OpenXMLDocumentAndCheckHash. With a document, it reads CurrentUser.ID and LastSaveSlot, clamps the slot to at least zero, and scans Warriors. It skips records whose IsFake string equals the literal True, then matches both SaveSlot and current user ID. If no current Warrior is found, it loads usersDefaultWarrior.xml, assigns the active SaveSlot, imports the Warrior into the shared document and parses it. The observed clamp has no upper bound of three; the four-slot menu contract is a separate UI boundary. A null document takes a logged empty-roster fallback. Full constructor, migration and failure semantics remain unverified.

GameSettings.LoadVersion (`0xE1DAF0`) first attempts the primary XML and, when that open returns null, attempts users_backup.xml. If the backup loads, it requests saving that document to the primary path before continuing version inspection. A loaded document with a missing Root takes a separate missing-data/version path; the initial primary-open fallback alone does not establish that every malformed structure is recoverable. The native XML loader and complete startup ordering remain under analysis. No backup restoration was performed on real files.

OpenXMLDocument's path/file overload (`0x15CBD40`) concatenates the path and optional slash/filename, creates XmlReaderSettings and sets IgnoreComments. Open type 0 chooses external storage when the path starts with CurrentStorage, otherwise ResourceManager.GetText; type 1 selects Resources explicitly and type 2 external storage. Its text overload (`0x15CBB20`) returns null for empty data and constructs a StringReader/XmlReader/XmlDocument otherwise. XML parse exceptions and unwinding are not inferred as null returns. OpenXMLDocumentAndCheckHash (`0x15CC4C0`) calls the checker for types 0/2 when a document exists, then returns the document; the checker also has separate validity state. No Android encryption/signing rule is substituted for these observed routes.

AbstractRoster.SaveAttribute's string overload (`0xCFDB60`) looks up or appends the attribute on its XML node, sets its value, then calls UserDataWriter.Save(false). Numeric overloads stringify values first. This marks the writer dirty; it does not synchronously commit every attribute change. UserDataWriter.Save (`0xFC3FD0`) sets _NeedSave for normal requests and dispatches SaveToFile directly for forced requests.

Roster.SaveToFile (`0xFDF620`) serializes its XML document, obtains ListSF.UsersPath (`0xD0F750`) and calls XmlUtils.SaveDocumentAndUpdateHash (`0x15CC660`). That function calls FilesUtil.SaveXmlFile then UserDataValidator.UpdateFileHash. Android signing-certificate/device-ID assumptions have not been imported.

FilesUtil.WriteAllBytes_NintendoSDK (`0xED760`) performs an existing-file deletion check, creates the file, opens write mode, writes the byte buffer with flush option 1, closes it, and calls nn.fs.FileSystem.Commit. Relevant wrappers: Delete `0x75A00`, Create `0x759C0`, Open `0x75AA0`, Write `0x75900`, Close `0x759B0`, Commit `0x75B80`. Error results are checked; exact failure behavior and atomic recovery still require analysis.

Future Windows replacement must preserve profile/slot separation and schema/hash semantics, provide durable writes and test interrupted writes, invalid/missing files, deletion, and switching profiles. No save migration or new Windows save writer has been implemented.
''')
    if (ROOT/'reports/native-save-scheduler.json').exists():
        scheduler=read('reports/native-save-scheduler.json');report=ROOT/'reports/save-research.md'
        report.write_text(report.read_text(encoding='utf-8')+f'''
Save scheduler validation: OnTimerTick (`0xFE43A0`) resets the request count when unscaledTime - lastReset is **strictly greater than 60.0f**, stores a second unscaledTime read as the reset time, and dispatches dirty writers in list order while count < 4. Base SaveToFile (`0xFC5870`) clears the flag and increments the int32 count. Forced requests bypass the timer budget. {scheduler['cases']} cases / {scheduler['checks']} comparisons cover exact/adjacent reset times, empty/mixed lists, request order, force dispatch and counter boundaries. The Unity clock is fixture-supplied; virtual targets use the original base writer, which performs no XML IO. Roster subclasses and failed writes remain separate. Evidence: reports/native-save-scheduler.json.
''',encoding='utf-8')
    write('reports/local-sparring.md',f'''# Switch local versus evidence

Updated {now}. Static analysis only; no two-controller gameplay test occurred.

The original Pvp scene is level8 and contains PvpScene. PvpScene metadata includes PlayerOneInput and PlayerTwoInput, independent character templates, location selection and controller-switch methods.

The original level7 MenuItemButton component **540** has an enabled UnityEvent binding to GeneralMenuScene component **587**, method **ShowPvp** (void call mode 1; the stored string argument is gotoSparring). The binding is reproduced from the sequential component decode in analysis/assets/pvp-entry-bindings.json. ShowPvp (`0xE6ED90`) starts a delay coroutine. Its MoveNext (`0xE6F970`) unsubscribes controls, waits approximately 0.12 seconds, sets ListSF.GameMode to **2**, clears DelayCoroutine, and calls GoToModule with module **8**. This entry path does not read AssemblyController.ShowPVP. The shared AssemblySettings ShowPVP=0 value therefore does not establish that Switch Sparring is disabled.

PvpScene static initializer (`0xD974D0`) allocates two InputData objects using distinct player/control indices `(0, 2, 0)` and `(1, 2, 1)`. HaveSecondPlayer (`0xD94FD0`) reads GamePadController.DevicesCount and tests greater than one. StartFight (`0xD961F0`) resolves `PvpBattle|pvp|1`, clears fight lists, obtains the two selected model parameter sets with player IDs 0 and 1, and adds them as player/warrior before entering the fight flow. Input switching methods are at `0xD971B0`, `0xD97380`, `0xD97260`, `0xD97430`.

This identifies the local versus implementation separately from residual MultiplayerSF raid/social classes. Device ownership, Joy-Con splitting, disconnect/pause, character unlock rules and every match outcome still require deeper tracing and runtime tests.
''')
    write('reports/asset-integrity.md',f'''# Asset recovery integrity

Updated {now}. These are extraction/inspection results; no Unity Editor import or Windows launch occurred.

- Original serialized source: {len(source['files'])} files, {source['total_objects']} objects. Every object has original file/path ID, bounded byte extent and SHA-256 in analysis/assets/source-objects.jsonl.
- TextAssets: **{source['exact_text_payload_matches']}/{source['text_assets']}** exact exported-payload matches. All 526 XML documents in content-v2 parse; 559 custom animation files pass bounded validation.
- Source class counts: {json.dumps(source['class_counts'],ensure_ascii=False)}.
- Component graph: {graph['raw_identity_checks']}. Original references: {graph['reference_counts']}. Generated prefab/editor references are explicitly separated from the original external-file tables.
- All 3,344 MonoBehaviours return parseable JSON in a clean sequential pass. Four records changed from the first parallel pass; originals and differences are retained in sequential-summary.json. JSON success does not imply complete field-layout correctness.
- Remaining known warning: resources.assets path ID 15328, ScreenModel, has an actual **32-byte header and no custom payload**. Its missing custom fields cannot be recovered from nonexistent bytes. Recorded component graph incoming edges: {screen_references}; this graph does not include every Resources dynamic lookup. GUISkin also reports an invalid script ID. Raw bytes are preserved.
- Visual spot checks performed on exported SwitchControllers.png, FightPVP.png and dojo_bg.png: controller art/buttons, packed versus UI elements and layered landscape are visible and coherent. This checks representative decode plausibility, not every texture or original on-screen compositing.
- Exported Switch shader YAML/native programs are retained for analysis. Windows-compatible shader behavior has not been recovered or tested. Audio, meshes, fonts, sprite rectangles and streaming resources require further per-type verification.

No original source-project GUID recovery is claimed. AssetRipper-generated Unity GUIDs are distinct from preserved serialized external GUIDs/path IDs. No visual or gameplay parity PASS is claimed.
''')
    native=sqlite3.connect(ROOT/'analysis/nso/corpus.sqlite')
    groups=collections.defaultdict(list)
    for rva,name in native.execute('SELECT DISTINCT rva,name FROM aliases WHERE name LIKE ?',('nn.%',)):
        type_name=name.split('$$')[0]
        group='.'.join(type_name.split('.')[:2]) if type_name.count('.')>=2 else 'nn.core'
        groups[group].append((rva,name))
    replacements={'nn.fs':('Windows filesystem plus durable per-profile/per-slot storage','save/load/delete, interrupted-write and mount-path tests'),
      'nn.account':('Local profile identity and selection','four independent slots per profile; profile switching'),
      'nn.hid':('Windows controller backend and device ownership','two controllers, Joy-Con-equivalent mappings, reconnect, vibration'),
      'nn.oe':('Windows lifecycle/window/power adapter','focus loss, suspend/resume and pause'),
      'nn.err':('Local diagnostic/error presentation','mapped failures with actionable logs')}
    matrix=[]
    for group,methods in sorted(groups.items()):
        replacement,test=replacements.get(group,('Investigate adapter against actual reachable call paths','prove runtime reachability, then test replacement or removal'))
        callers=set()
        for rva,name in methods:
            callers.update(n for n, in native.execute('SELECT DISTINCT f.name FROM calls c JOIN functions f ON f.rva=c.caller_rva WHERE c.callee_rva=?',(rva,)))
        matrix.append(dict(dependency=group,observed_methods=len(methods),examples='; '.join(name+' @'+hex(rva) for rva,name in methods[:4]),
            direct_call_sites='; '.join(sorted(callers)[:8]),replacement=replacement,required_test=test,status='OBSERVED_STATIC_RUNTIME_REACHABILITY_IN_PROGRESS'))
    native.close();csv_out('reports/platform-dependency-matrix.csv',matrix)
    features=[
      ('Story','Switch campaign and rebalance','Native root Include order maps 165 quests across 4 files; potential attachments reach 559 definitions in 15 files; exact branch/reward parity pending','IN_PROGRESS','reports/quest-loading-graph.json'),
      ('Sensei story','Playable Sensei arc','Native root loading includes all 30 Sensei quest definitions; event/progression execution pending','IN_PROGRESS','reports/quest-loading-graph.json + internalSettings'),
      ('Equipment/economy','Switch catalog, prices and rewards','32/64-bit currency codecs and balance getters checked against original ARM64; setter arithmetic checked at explicit persistence/statistics boundaries; full rewards/prices pending','IN_PROGRESS','reports/economy-research.md'),
      ('Local Sparring','Two local players and Switch match flow','Serialized menu callback and native mode-2/module-8 route identified; separate player inputs, controller count and fight start traced','IN_PROGRESS','reports/local-sparring.md'),
      ('Save slots','Four slots per Nintendo profile','Serialized menu bindings prove slots 0..3; save/write native chain identified','IN_PROGRESS','reports/save-research.md'),
      ('Redesigned UI','Switch interface and controller prompts','10 original scene files, Switch/PvP atlases and field graph exported','IN_PROGRESS','reports/asset-integrity.md'),
      ('Offline play','No server dependence for core modes','SkipContentDownload/SkipPayment settings present; residual networking requires reachability audit','IN_PROGRESS','internalSettings + native corpus'),
      ('Removed mobile modes','Energy/ads/IAP/raids/Forge/Ascension absent from playable Switch release','Residual mobile code/data exists; reachability/gates must be validated rather than deleted blindly','IN_PROGRESS','reports/switch-vs-mobile.md'),
      ('Combat/animation','Original speed and hit timing','Original ARM64 capsule, first-contact, damage-slice, Bezier and animation sample/physics coupling comparisons pass; full combat/scheduling remains unfinished','IN_PROGRESS','reports/combat-timing.md'),
      ('AI','Original decision tables and difficulty policy','All 6084 table blocks bounded/decoded; native interval/candidate checks pass; full policy remains unfinished','IN_PROGRESS','reports/ai-data-recovery.md'),
      ('Native Windows build','Independent x64 executable','Deferred by latest user instruction to stop after reverse engineering','OUT_OF_SCOPE','STATUS.md'),
      ('120 FPS','Measured render performance without timing changes','No executable, gameplay timing or FPS measurement in this phase','OUT_OF_SCOPE','reports/performance')]
    csv_out('reports/feature-parity.csv',[dict(feature=f,required=r,evidence=e,status=s,source=p) for f,r,e,s,p in features])
    write('reports/switch-vs-mobile.md','''# Switch versus mobile evidence policy

The supplied base + 1.1.0 patch is the only authoritative game-code/data input. No Android APK or mobile game assets were acquired. Guide/mod repositories are format references unless a specific equivalent native method and schema can be demonstrated.

Switch-specific evidence includes two-player PvpScene inputs/controller switching, four serialized save-slot bindings, Nintendo account/filesystem wrappers, controller prompt atlases and Sensei quest data. See local-sparring.md, save-research.md and asset-integrity.md.

Residual mobile raids/social/ads/Forge/energy classes and settings remain in the binary/data. Their presence is not evidence of an available Switch mode. Internal settings even retain mobile-facing flags; compile-time stubs and platform entry paths must decide reachability. SystemProperties.SetFrameRate, for example, is a single RET here despite its meaningful mobile-facing name.

The master specification's removed-mode list is an acceptance requirement. It is not automatically marked verified from source names or a mobile guide. Offline progression, balancing, all removed-mode gates and shortened duel waits still need explicit native/runtime checks.
''')
    write('reports/license-notes.md','''# Authorization and tool licenses

The user supplied the local game archives and keys and stated authorization for this private analysis. The work records that statement; it does not establish redistribution rights or provide a legal opinion. Inputs, keys, decrypted code, extracted assets and reconstructed proprietary code remain local and ignored by Git. No public remote is configured.

Tool source/version/license pins and release hashes are in toolchain-lock.json and repo-triage.md. Third-party tool distributions retain their own notices. Cpp2IL's local MIT-source patch is preserved separately. The source-only Gymnast GPL animation importer was consulted as a format reference; bundled game assets/add-ons were not fetched or executed. Original bounded parsers and research infrastructure do not include commercial SDK or game code.

Unicorn 2.1.4 is used solely as a portable local ARM64 research dependency; the wheel hash matches PyPI's published digest. Core GPL-2.0 and binding BSD notices remain with its distribution. Primary sources: https://github.com/unicorn-engine/unicorn/releases/tag/2.1.4 and https://pypi.org/project/unicorn/2.1.4/ . No Unicorn-based game launcher or port dependency has been created.

REA's fixed-NTFS native self-test cannot run on this removable exFAT USB. No C-drive workaround, system installation, drive formatting or host agent configuration change was performed. Headless Ghidra is the working native-analysis path.
''')
    audio_path=ROOT/'analysis/assets/audio-decoded/summary.json'
    tactics_path=ROOT/'analysis/assets/tactics-decoded-v2/summary.json'
    if audio_path.exists():
        audio=read('analysis/assets/audio-decoded/summary.json')
        report=ROOT/'reports/asset-integrity.md'
        report.write_text(report.read_text(encoding='utf-8')+f'\nAudio recovery: {audio["total"]} FSB5 banks decoded; {audio["status_counts"]}. PCM sample counts, channels and rates match bank metadata. Original loops are retained in the manifest; listening/mixing parity remains untested. Output: analysis/assets/audio-decoded. Official vgmstream release identity/digest: reports/vgmstream-lock.json.\n',encoding='utf-8')
    if tactics_path.exists():
        tactics=read('analysis/assets/tactics-decoded-v2/summary.json')
        report=ROOT/'reports/asset-integrity.md'
        report.write_text(report.read_text(encoding='utf-8')+f'\nAI tactic recovery: {tactics["total"]} entries; {tactics["status_counts"]}. The former version_candidates field records initial table-type observations, not file-format versions. Native readers now identify multiple typed blocks per archive; reports/ai-data-recovery.md documents the complete bounded schema checks. Original compressed/decoded hashes remain retained. AI policy runtime parity remains unverified.\n',encoding='utf-8')
    node_path=ROOT/'reports/native-node-integration.json'
    if node_path.exists():
        node=read('reports/native-node-integration.json')
        report=ROOT/'reports/combat-timing.md'
        report.write_text(report.read_text(encoding='utf-8')+f'''
Native integration validation: ModelNode.TimeStep (`0xFEBD80`) and its six real Vector helpers were executed with read-only original ARM64 text and synthetic initialized objects. A separately compiled C# model matches {node['cases']} cases across {node['steps']} node ticks and {node['bit_exact_float_checks']} bit-exact floating-point checks. Exact artifact hashes and scope are in reports/native-node-integration.json.

The validated update is delta = current - previous; apply delta *= (1 - attenuation) only for a physics node; next = current + delta; add the supplied gravity to next.Y; then previous = current and current = next. Every native float operation is retained in order. The gravity addition also occurs when the node flag is false; the caller decides which nodes receive a step.

ModelPhysics.TimeStep (`0xE99140`) skips fixed nodes and steps nodes according to StartPhysics, IsPhysics and shock state. Its gravity getter (`0xE99520`) divides PhysicsController.Gravitation by GameUtils.SlowMode squared. The getter's original native calls are included in the v2 numeric checks for positive slow-mode values. Constraint solving, collision/damage ordering, animation-to-physics coupling and whole-fight replay remain unverified. This is not a measured game frame rate.
''',encoding='utf-8')
    contact_path=ROOT/'reports/native-contact-geometry.json'
    if contact_path.exists():
        contact=read('reports/native-contact-geometry.json')
        report=ROOT/'reports/combat-timing.md'
        report.write_text(report.read_text(encoding='utf-8')+f'''
Contact geometry validation: Vector2f.GetEquationLine (`0x15C4A90`) and IsDistanceStrike (`0x15C50A0`) match a compiled C# reference over {contact['cases']} finite nondegenerate cases and {contact['checks']} checks. This covers normalized line coefficients, capsule endpoint inclusion and projection mutation, including boundary/tangent cases, with zero game-function mocks. Evidence: reports/native-contact-geometry.json.
''',encoding='utf-8')
    def audit(path):
        p=ROOT/path
        return {r['file']:r for r in read(path)['assemblies']} if p.exists() else {}
    for path,label in [('reports/native-capsule-geometry.json','Complete finite nondegenerate capsule/segment math'),('reports/native-strike-selection.json','First intersecting edge in list order and no-hit state retention'),('reports/native-damage-combination.json','Internal damage combination slice; upstream factors supplied as inputs'),('reports/native-animation-bezier.json','Original Bezier recurrence and midpoint sampling'),('reports/native-animation-step.json','Original animation draw-step and physics point coupling')]:
        if (ROOT/path).exists():
            result=read(path);report=ROOT/'reports/combat-timing.md'
            report.write_text(report.read_text(encoding='utf-8')+f"\n{label}: {result['cases']} cases / {result['checks']} comparisons pass. Scope: {result['scope']} Evidence: {path}.\n",encoding='utf-8')
    moves_path=ROOT/'reports/move-template-resolution.json'
    if moves_path.exists():
        moves=read('reports/move-template-resolution.json');report=ROOT/'reports/combat-timing.md'
        report.write_text(report.read_text(encoding='utf-8')+f"\nTemplate interpretation applies native depth-first parent order and first-existing-attribute precedence to all {moves['moves']} moves. The 22 moves lacking explicit filenames resolve as {moves['filename_classifications']}. Six original ShortAttack references are logged/skipped by native parser behavior; no replacement template was invented. Ordered raw event/interval candidates are preserved, not certified instantiated objects. See reports/move-template-resolution.json and analysis/assets/moves-resolved-v1. The null/empty filename loader branch separately passes 256 original-code checks without resource IO (reports/native-empty-animation-gate.json).\n",encoding='utf-8')
    quest_path=ROOT/'reports/quest-loading-graph.json'
    if quest_path.exists():
        graph=read('reports/quest-loading-graph.json');lookup=read('reports/native-quest-lookup.json')
        write('reports/story-quest-research.md',f'''# Quest loading and identity

Updated {now}. Static loading graph plus bounded original ARM64 lookup/comparator execution; no completed story playthrough.

ListSF.ParseQuests (`0xD12370`) records a filename in its attached-file set before loading it, processes XML children in order, constructs Quest nodes and recursively loads Include File references. QuestActionAttachFile.Parse (`0xD73F40`) reads the literal File attribute; RunAction (`0xD74010`) invokes the same loader. The root quests.xml includes the Sensei extension directly.

The initial Include graph has {graph['initial_files']} files / {graph['initial_quest_definitions']} definitions, including {graph['sensei_quest_definitions']} Sensei definitions. Potential AttachQuestFile actions reach {graph['potential_files']} files / {graph['potential_quest_definitions']} definitions. All referenced files exist. Potential closure ignores conditions and event execution; its order is not claimed as the actual order of dynamic attachments.

One quest name occurs twice, in the eclipse extension and zone 4 story. AddQuest (`0xE11050`) registers event-list memberships and appends to questsAll without a name-deduplication check. GetQuestByName (`0xE122C0`) returns the first ordinal string match. Both definitions are retained. Native lookup matches {lookup['lookups']} compiled-reference queries, including that duplicate, null/empty queries and synthetic UTF-16 names.

QuestStage.CompareTo (`0xE14F00`) uses descending integer priority when the other quest's CompleteType is not QUEST_ACTIONS. If the other is QUEST_ACTIONS (enum value 1), it returns +1 when this quest is also QUEST_ACTIONS, otherwise -1. This observed special case is retained, including +1 for ACTIONS/ACTIONS. All {lookup['comparisons']} state/priority boundary pairs match the original instructions. Whether both compared quests can simultaneously occupy that state remains a scheduler reachability question. SortActionQuest sorts compareQuests and then assigns sequential indexes; questsAll registration order is separate.

Evidence: reports/quest-loading-graph.json, reports/native-quest-lookup.json, analysis/assets/quest-loading-v1 and analysis/nso/quest-loading-trace-v1. Quest condition/expression semantics, event cancellation, reentry, checkpoint/resume and every reward/economy transition remain IN_PROGRESS.
''')
    if (ROOT/'reports/native-wallet-arithmetic.json').exists():
        codec=read('reports/native-currency-codec.json');long_codec=read('reports/native-currency-long.json');wallet=read('reports/native-wallet-arithmetic.json')
        write('reports/economy-research.md',f'''# Currency representation and wallet arithmetic

Updated {now}. Original ARM64 code and compiled research references; no real save was opened or changed.

Generic currency counters use a 16-byte ObscuredInt value: currentCryptoKey at +0, hiddenValue +4, fakeValue +8, inited byte +12. CurrencyStruct stores its currency reference at +0x10 and count at +0x18. Constructor, reference identity, aggregate getter/setter, XOR conversions, zero-key fallback and lazy initialization match {codec['cases']} cases / {codec['checks']} checks. Original code: constructor 0xD3D2C0, conversion pair 0x7926A0 / 0x794890, unboxed InternalDecrypt 0x7A8F20. Absent, inactive and active-consistent detector states are covered; the mismatch callback is outside scope.

Money and Bonus use separate 32-byte ObscuredLong values: 64-bit key/hidden/fake words at +0/+8/+0x10 and inited byte +0x18. Roster stores Money at +0x118, Bonus at +0x138, PaidMoney at +0x158 and PaidBonus at +0x178. The two decoded balance getters operate on copies, so lazy initialization there does not initialize the original roster field. Codecs, full Money/Bonus getters and the indirect-result PaidBonus getter match {long_codec['cases']} cases / {long_codec['checks']} checks, including signed boundaries and nonzero upper words. Original conversions 0x792BB0 / 0x7A1DD0, unboxed decrypt 0x7A9C70, getters 0xFD4B70 / 0xFD4C20 / 0xFD50B0. The +0x158 PaidMoney layout is observed in DenominateMoney; its complete getter/setter behavior is not certified by these checks.

SetMoney (0xFD0880) obtains pow(10, denominationDigits at roster +0x218), converts to int64 with ARM64 FCVTZS, and selects at least 1 as the persistence multiplier. The protected in-memory Money receives the supplied value; SaveAttribute receives that value multiplied by the multiplier with native 64-bit wraparound. The post-pow instructions through the SaveAttribute call arguments are tested; the imported pow implementation and XML persistence are not executed by this slice.

SetBonus (0xFD0990) always writes the new Bonus. Type 0 skips PaidBonus bookkeeping. For nonzero type, an increase with isPaid adds the absolute native difference to PaidBonus; an unpaid increase leaves it unchanged. A decrease subtracts max(0, delta - oldBonus + paidBonus), which consumes free bonus first for ordinary nonnegative valid balances. Native unchecked overflow behavior is retained in the research reference. Equal balances leave PaidBonus unchanged. Increased balances proceed to a statistics allocation after the balance writes.

The setter checks cover {wallet['cases']} cases / {wallet['checks']} comparisons. Their boundaries are explicit: SaveAttribute is observed then returned without executing XML persistence; increases stop before statistics allocation. These are arithmetic/dataflow checks, not a successful saved transaction. Original long Max at 0x663F30 is executed. The Money slice starts at 0xFD08D0 with a supplied pow result and stops at 0xFD0978 before SaveAttribute.

QuestActionGiveCurrency RunAction (0xD83520) obtains expression-derived type/value pairs (GetValues 0xD83760), then adds Money/Bonus as int64; Bonus uses reason 6 and isPaid=false. Generic currencies use an int32 conversion before AddCurrencyCount (0xFDE550). QuestActionTakeCurrency's native helper is 0xD901E0. These actions still require complete expression/reachability and reward-condition analysis. ListSF.ChangeAddGold (0xD1ACA0) and ChangeAddBonus (0xD1AED0) reject a negative wrapped sum before calling setters; this guard is separate from direct setter behavior. Residual network and mobile callers are present and are not proof of Switch availability.

Evidence: reports/native-currency-codec.json, reports/native-currency-long.json, reports/native-wallet-arithmetic.json; private typed-menu-currency-gates-layout-v2, typed-currency-codec-pvp-layout-v2 and typed-currency-long-persistence corpora. Complete prices, equipment upgrades, reward ordering, story conditions, denomination migration, XML schema/failure recovery and playable economy parity remain IN_PROGRESS.
''')
    recovery_run=read('reports/cpp2il-corrections-lock.json').get('recovery_run','nso-value-types-v9')
    before=audit('analysis/il2cpp/cil-audit-nso-metadata/summary.json');after=audit(f'analysis/il2cpp/cil-audit-{recovery_run}/summary.json')
    stack=read(f'reports/cil-stack-audit-{recovery_run}.json')
    direct=read(f'reports/recovered-scalars-{recovery_run}.json')
    isolated=read(f'reports/recovered-scalars-isolated-{recovery_run}.json')
    stack_rejections=sum(row.get('methods_with_stack_rejection_diagnostics',0) for row in after.values())
    legacy=audit('analysis/il2cpp/cil-audit-nso-legacy-vtable/summary.json')
    helper_reduction=sum(legacy[name]['methods_with_recovery_helper_calls']-after[name]['methods_with_recovery_helper_calls'] for name in ['Assembly-CSharp.dll','Assembly-CSharp-firstpass.dll'])
    scoped_csharp=read('reports/scoped-csharp-type-audit.json')
    identity_path=f'reports/recovered-allocation-identity-{recovery_run}.json'
    identity=read(identity_path) if (ROOT/identity_path).exists() else {}
    source_build_path=f'reports/recovered-source-build-{recovery_run}.json'
    source_build=read(source_build_path) if (ROOT/source_build_path).exists() else {}
    source_project_path=f'reports/recovered-source-project-build-{recovery_run}.json'
    source_project=read(source_project_path) if (ROOT/source_project_path).exists() else {}
    legacy_path=f'reports/recovered-source-legacy-reference-check-{recovery_run}.json'
    legacy_source=read(legacy_path) if (ROOT/legacy_path).exists() else {}
    profile_path=f'reports/recovered-source-profile-legacy-reference-check-{recovery_run}.json'
    profile_source=read(profile_path) if (ROOT/profile_path).exists() else {}
    member_path=f'reports/recovered-default-member-{recovery_run}.json'
    default_member=read(member_path) if (ROOT/member_path).exists() else {}
    class_path=f'reports/recovered-class-guards-{recovery_run}.json'
    class_guards=read(class_path) if (ROOT/class_path).exists() else {}
    sample_path=f'reports/scoped-source-build-{recovery_run}.json'
    sample=read(sample_path) if (ROOT/sample_path).exists() else {}
    correction_checks=read('reports/cpp2il-corrections-lock.json').get('harness_passed',154)
    quality=read('reports/native-pseudocode-quality.json') if (ROOT/'reports/native-pseudocode-quality.json').exists() else {}
    comparison=[]
    for name in ('Assembly-CSharp.dll','Assembly-CSharp-firstpass.dll'):
        if name in before and name in after:
            a,b=before[name],after[name]
            comparison.append(dict(assembly=name,bodies=b['with_bodies'],previous_helper_methods=a['methods_with_recovery_helper_calls'],
                current_helper_methods=b['methods_with_recovery_helper_calls'],current_diagnostic_methods=b['methods_with_diagnostic_strings'],
                helper_method_reduction=a['methods_with_recovery_helper_calls']-b['methods_with_recovery_helper_calls'],stack_rejection_diagnostic_methods=b.get('methods_with_stack_rejection_diagnostics',0)))
    native=read('analysis/nso/corpus-summary.json')
    typed_path=ROOT/'analysis/nso/scoped-type-application.json'
    typed=read('analysis/nso/scoped-type-application.json') if typed_path.exists() else {}
    failed_native=sum(count for status,count in native.get('by_status',{}).items() if status!='PSEUDOCODE_EXPORTED')
    additional=native.get('additional_native_addresses',native.get('unique_records',0)-native.get('metadata_unique_addresses',0))
    remaining_native=(f"All {native['metadata_unique_addresses']:,} distinct metadata-linked addresses now have native pseudocode exports, plus {additional} explicitly identified registration/runtime helpers. The last failing regex method at 0x700970 was repaired by independently validating three signed-relative switch tables: all 176 guarded indices were executed in original ARM64. Ghidra body coverage grew from 9,400 to 46,880 bytes and the subsequent export succeeded. See analysis/nso/regex-switch-repair.json and native-regex-switch-repair-v1. This does not prove regex semantics or comprehensively decompile native engine functions outside the selected address sets." if failed_native==0 else
        f'{failed_native} native high-level exports still fail. Prior regex timeout/disassembly logs are retained. Inspect the latest corpus and exact error logs before making a completion claim.')
    write('reports/decompilation-quality.json',json.dumps(dict(native=native,scoped_types=typed,cil_comparison=comparison,
        validated_unwind_ranges=read('reports/native-unwind-inventory.json') if (ROOT/'reports/native-unwind-inventory.json').exists() else None,
        unwind_range_exports=read('reports/native-unwind-recovery.json') if (ROOT/'reports/native-unwind-recovery.json').exists() else None,
        recovery_run=recovery_run,stack_depth_and_headers=stack,recovered_cil_direct_execution=direct,recovered_cil_isolated_accessors=isolated,
        static_allocation_identity=identity,complete_game_assembly_source_compilation=source_build,native_pseudocode_quality=quality,
        project_export_compilation=source_project,scoped_clean_source_compilation=sample,
        compatible_legacy_reference_compilation=legacy_source,
        profile_decompiler_legacy_compilation=profile_source,native_default_member_restoration=default_member,
        native_class_guard_correlation=class_guards,
        scoped_csharp_types=read('reports/scoped-csharp-type-audit.json') if (ROOT/'reports/scoped-csharp-type-audit.json').exists() else None,
        currency_aggregate_abi=read('reports/arm64-currency-abi-gap.json') if (ROOT/'reports/arm64-currency-abi-gap.json').exists() else None,
        expanded_type_scopes={name:read('analysis/nso/'+name+'-type-application.json') for name in ['behavior-ai-layout-v2','combat-layout-v2','combat-prototype-repairs-v2','geometry-layout-v2','damage-attributes-layout-v2','animation-bezier-layout-v2','quests-loading-layout-v2','menu-currency-gates-layout-v2','currency-codec-pvp-layout-v2','currency-long-persistence','save-slot-persistence','save-writer-slot-schema','save-switch-load-fallback','save-roster-initialization','save-xml-hash-fallback'] if (ROOT/('analysis/nso/'+name+'-type-application.json')).exists()},
        full_semantic_reverse_engineering='NOT_COMPLETE',recovered_csharp_buildable=False,
        limitation='Exported pseudocode and syntactically parseable CIL are not equivalent to original source or validated behavior.'),indent=2)+'\n')
    write('reports/decompilation-quality.md',f'''# Decompilation quality and unresolved work

Updated {now}. Full clean decompilation suitable for a later complete OS port is the primary goal and is **NOT COMPLETE**. Reverse engineering supports this goal. Acceptance gates: reports/decompilation-acceptance.json.

Native corpus: {native.get('unique_records')} records; statuses {native.get('by_status')}. This includes {additional} explicitly identified native registration/runtime helpers in addition to {native['metadata_unique_addresses']:,} distinct metadata-linked addresses. All metadata addresses independently match registered native method/generic pointer tables.

{remaining_native}

The NSO's MOD0-linked exception table provides a separate inventory: 152,904 FDE/CIE ranges validate with no overlaps, and all 83,673 managed metadata addresses match exact starts. The initial corpus had no pseudocode at 69,106 other range starts. Native-engine recovery now uses these proven bounds; current progress is reports/native-unwind-recovery.json. These ranges cover 36,292,460 of 37,181,704 text bytes. Remaining text includes material outside this inventory and must be classified separately; neither range membership nor pseudocode proves semantics. The decoder follows the primary LSB exception-header encoding specification and checks the pinned LLVM 18.1.8 parser's FDE/CIE conventions. References are recorded in reports/native-unwind-inventory.json.

Scoped type application: {typed.get('methods_typed','pending')} methods, {typed.get('metadata_slots_typed','pending')} metadata slots; {len(typed.get('errors',[]))} recorded type errors. Exact report: analysis/nso/scoped-type-application.json. The Hit layout gate matches the known native damage offset `0x1C`.

That line describes the latest application pass. Additional preserved scope reports cover all 2,853 combat methods, the 50 anonymous-parameter repairs, the 224 behavior/AI targets and 102 geometry methods. Original partial errors and successful repair overlays are retained separately. See expanded_type_scopes in the JSON report.

Measured recovered-CIL comparison after correcting the legacy virtual-table offset and recovering stripped allocation/class-initialization helpers:

{json.dumps(comparison,indent=2)}

Many diagnostic/helper bodies remain. Earlier whole-project ILSpy exports under analysis/il2cpp/cpp2il-csharp-nso-metadata are partial and have per-assembly exit code **70**. The preserved v4 TacticalTableHolder/Vector2f exports retain correct BinaryReader targets. Latest {recovery_run} VersionContainer/Triangle exports retain {scoped_csharp['warning_total']} operand-type warnings. An exported helper-free body can still be invalid. See reports/scoped-csharp-type-audit.json. The opcode/operand CIL audit is syntactic and does not verify stack types or semantic behavior.

The two game assemblies have {helper_reduction:,} fewer helper-bearing methods than the legacy-vtable pass. This is a syntax/recovery metric, not semantic proof; rejecting unsafe inferred exception helpers can increase unresolved calls, and rejected bodies can reduce helper counts. The correction harness now passes {correction_checks} checks, including four synthetic allocation-emission checks. All 44 latest assemblies have zero malformed bodies under the limited syntax audit. Complete single-file C# compiler experiment status: {source_build.get('status','pending')}. Per-type project export/compiler status: {source_project.get('status','pending')}. Its .NET 10 reference environment is diagnostic and is not a Unity/game build. Declaration/reference errors can prevent later method-body diagnostics from appearing; low diagnostic counts do not establish closeness to clean source.

The scoped Credentials/AuthenticationTypes source experiment is {sample.get('status','pending')}. This compiles the unchanged two-type ILSpy output without recovered dependency DLLs or replacement bodies. It is a small library-data source sample, not recovered playable combat. The source marker-only view preserves a whitelist of metadata-listed markers but omits other original attributes, including serialization-relevant contracts; the tool-annotated view and original metadata remain separate evidence. The omitted metadata is a required recovery task, so this view is not a complete Unity source project.

Observed mscorlib/System assembly identities are 2.0 and System.Core is 3.5, copied from original metadata by the pinned Dumper. The runtime backend remains IL2CPP. Official Microsoft .NET 3.5 reference metadata, verified by published catalog SHA512 and NuGet package signature/timestamp, enables a closer compiler context without installing a host framework. Compatible-reference compiler results are in {legacy_path}: status {legacy_source.get('status','pending')}. This check reaches body errors in main while firstpass can still stop at declaration errors. Diagnostic counts include cascades and do not count independent fixes.

Native-backed DefaultMember restoration is {default_member.get('status','pending')}, with {default_member.get('recovered_attributes','pending')} emitted arguments decoded and matched to actual metadata properties. A strict cache-generator shape and constructor identity, three-family/shared-string-wrapper consensus, and an independently executed native UTF8/constructor path support this restoration. The ListWrapper project output now renders a real indexer. Other attribute arguments remain incomplete.

A separate decompiler input view preserves game DLL bytes and substitutes only matching framework metadata with official unstripped legacy references. This resolves standard-library accessor/name contracts and preserves anonymous-type definitions during project export. Its actual compatible-reference body compiler results are {profile_source.get('status','pending')}; see {profile_path}. Both assemblies still fail with many invalid casts, arithmetic, visibility, missing-member and call errors. These are compiler observations, often cascaded, not counts of independent source fixes or a completion percentage.

The v10 stack audit found 35,384 understated MaxStack headers, 1,018 stack-flow failures and 44 injected helper types with no base. Headers had been left at zero while automatic computation was disabled. The generator now computes each header inside the per-method error boundary, rejects invalid stack flow explicitly and gives its injected helper a System.Object base. Latest stack audit status: {stack['status']}, understated headers {stack['understated_max_stack']}, stack-flow failures {stack['stack_flow_failures']}, helper types without a base {stack['helper_types_without_base']}. The syntax audit records {stack_rejections} stack-rejection diagnostic bodies; they deliberately throw a recovery error and are not original behavior. A valid stack depth does not establish valid operand types.

Eight original native scalar accessors produce 768 cases / 1,760 checks, including bounds errors through the original exception factory and supplied runtime boundaries. Direct recovered-type execution status is {direct['status']} ({direct['failure_count']} failures in {direct['cases']} attempted cases); static initialization remains part of that test. Isolated recovered accessor status is {isolated['status']} ({isolated['failure_count']} failures in {isolated['cases']} cases). Isolation replaces the one field load with an int-array argument and remaps metadata tokens; it retains all other instruction/branch bytes, local types and original stack limits. Its own reference getter/setter/bounds checks run first. This separation does not certify constructors or the recovered class as a whole.

The preserved v11 static identity witness fails: VersionContainer.Zero was System.Object although native allocation receives VersionContainer_TypeInfo. The emitter fused a later base constructor into allocation. The repair fuses only an adjacent same-type constructor within one block; other known reference types use explicit zeroed allocation with later initialization/calls retained. Latest independent static identity status: {identity.get('status','pending')}. Four synthetic emitted-CIL checks verify exact reference type, zeroed fields, no implicit instance constructor, and one explicit later constructor call. Complete class initialization and portable source semantics remain unverified. The original failure remains in reports/recovered-allocation-type-gap.json; new identity results are in {identity_path}.

Native-output quality is audited independently from exporter success: {quality.get('status','pending')}, snapshot {quality.get('counts',{})}. Warning markers include indirect flow and are not all independent defects. Listing addresses outside FDE bounds require explicit flow/boundary review; no automatic truncation is treated as a repair. Newly exported range records also retain decompiler messages and outside-frame byte counts.

Native exception/helper work: the actual raiser at 0xB4C880 is identified by its preserved incoming exception pointer, trace_ips access, eight-byte C++ exception wrapper and native throw tail, with three independent corlib method families agreeing. Thirty-two cases / 224 original-code comparisons reach explicitly supplied C++ allocation/throw boundaries; real unwinding and stack capture remain untested. Initial v5/v6 recovery aborted with Out of memory during full-text thunk decoding. The legacy NSO scanner now indexes fixed-width B/BL words without retaining a decoded object for every instruction; later recovery succeeds under the same heap limit. Legacy transitive raiser classification is restricted to the independently witnessed target, and unknown exception-factory guesses are left unresolved.

The native array allocator at 0xB5FE50 has normal allocation and conditional overflow paths. The earlier transitive exception-name heuristic incorrectly emitted an OverflowException allocation in place of an int array. Strict size/header/return-flow recognition, witnessed independently from String, BitConverter and Convert families, now recovers that call as array allocation. The original routine matches 582 cases / 3,468 comparisons at explicit initialized-class, element-size, allocation, memset and overflow boundaries. No GC/allocation-failure parity is implied. The VersionContainer source now contains new int[4] where the old export cast OverflowException to int[]. Boolean-result and integer/array-length propagation repairs address a separate source of invalid object-typed arithmetic; remaining warnings are counted above.

Ghidra .plt was initially non-executable in this loader's analysis model. All 656 16-byte thunks match original NSO text, the ADRP/LDR/ADD/BR layout and import GOT addresses. Only that analysis flag was corrected; no source code bytes or OS page permissions changed. Seventeen new native targets and three repaired import-thunk exports are retained separately. Imported stubs do not constitute the implementations of their external libraries.

The current ARM64 managed argument resolver consumes one integer register per non-floating parameter. Original ObscuredInt conversion/setter instructions consume both X1/X2 for one 16-byte value, and its return conversion produces X0/X1. The resolver's single argument/result operand model loses that distinction. Native-tested 32-byte ObscuredLong returns use X8, which the tool separately models as a hidden result buffer. The scoped audit identifies 14 ObscuredInt-return and 27 by-value-argument metadata records as review candidates; it does not claim every candidate is incorrect or reachable. Complete multiword entry/call/return/stack/SSA/CIL support is required before trusting those recovered bodies. See reports/arm64-currency-abi-gap.json.

The stock Dumper runtime header had class and array layouts inconsistent with the native binary. The v2 type archive gates static_fields=0xB8, vtable=0x128, array elements=0x20 and Hit.damage=0x1C. Old typed exports are superseded by typed-behavior-ai-layout-v2. Type names outside validated offsets still require individual review.

Native assembly confirms that FightScene.FixedUpdate is a five-instruction null check/tail call into Fight.Draw. Some Ghidra pseudocode expands the tail call and displays the Draw loop inside its caller. Reports identify the real machine-code location rather than treating the expanded pseudocode as original function boundaries.

Remaining substantive work includes full collision/damage/AI semantics, progression/reward/economy transitions, platform feature gates, save hash/schema and failure behavior, shaders and representative runtime comparisons. See feature-parity.csv. No Windows game build or FPS result is claimed.
''')
    print('Updated scoped behavior, integrity, platform and feature reports; four serialized save-slot bindings established.')
if __name__=='__main__':main()
