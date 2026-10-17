# Quest loading and identity

Updated 2026-10-17T08:26:34.003364+00:00. Static loading graph plus bounded original ARM64 lookup/comparator execution; no completed story playthrough.

ListSF.ParseQuests (`0xD12370`) records a filename in its attached-file set before loading it, processes XML children in order, constructs Quest nodes and recursively loads Include File references. QuestActionAttachFile.Parse (`0xD73F40`) reads the literal File attribute; RunAction (`0xD74010`) invokes the same loader. The root quests.xml includes the Sensei extension directly.

The initial Include graph has 4 files / 165 definitions, including 30 Sensei definitions. Potential AttachQuestFile actions reach 15 files / 559 definitions. All referenced files exist. Potential closure ignores conditions and event execution; its order is not claimed as the actual order of dynamic attachments.

One quest name occurs twice, in the eclipse extension and zone 4 story. AddQuest (`0xE11050`) registers event-list memberships and appends to questsAll without a name-deduplication check. GetQuestByName (`0xE122C0`) returns the first ordinal string match. Both definitions are retained. Native lookup matches 578 compiled-reference queries, including that duplicate, null/empty queries and synthetic UTF-16 names.

QuestStage.CompareTo (`0xE14F00`) uses descending integer priority when the other quest's CompleteType is not QUEST_ACTIONS. If the other is QUEST_ACTIONS (enum value 1), it returns +1 when this quest is also QUEST_ACTIONS, otherwise -1. This observed special case is retained, including +1 for ACTIONS/ACTIONS. All 441 state/priority boundary pairs match the original instructions. Whether both compared quests can simultaneously occupy that state remains a scheduler reachability question. SortActionQuest sorts compareQuests and then assigns sequential indexes; questsAll registration order is separate.

Evidence: reports/quest-loading-graph.json, reports/native-quest-lookup.json, analysis/assets/quest-loading-v1 and analysis/nso/quest-loading-trace-v1. Quest condition/expression semantics, event cancellation, reentry, checkpoint/resume and every reward/economy transition remain IN_PROGRESS.
