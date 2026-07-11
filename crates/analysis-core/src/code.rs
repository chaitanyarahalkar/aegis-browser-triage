use crate::{
    CapabilityEvidence, CapabilityMatch, CodeAnalysisReport, CodeAnalysisStats, Confidence,
    ExtractedString, FormatReport, SectionRecord, StaticBasicBlock, StaticCallTarget,
    StaticControlFlowEdge, StaticFunction, StaticInstruction, SymbolRecord,
};
use iced_x86::{Code, Decoder, DecoderOptions, FlowControl, OpKind};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

const MAX_CODE_BYTES: usize = 8 * 1024 * 1024;
const MAX_FUNCTIONS: usize = 2_048;
const MAX_BASIC_BLOCKS: usize = 8_192;
const MAX_BLOCKS_PER_FUNCTION: usize = 256;
const MAX_INSTRUCTIONS: usize = 50_000;
const MAX_INSTRUCTIONS_PER_FUNCTION: usize = 4_096;
const MAX_INSTRUCTIONS_PER_BLOCK: usize = 512;
const MAX_EDGES: usize = 16_384;
const MAX_CAPABILITY_EVIDENCE: usize = 16;
const MAX_SAFE_JS_ADDRESS: u64 = 9_007_199_254_740_991;

struct CodeRegion<'a> {
    file_offset: usize,
    address: u64,
    bytes: &'a [u8],
}

#[derive(Clone)]
struct FunctionSeed {
    name: String,
    source: String,
}

#[derive(Default)]
struct DecodeBudget {
    instructions: usize,
    blocks: usize,
    edges: usize,
    truncated: bool,
}

#[derive(Clone)]
struct Feature {
    kind: &'static str,
    normalized: String,
    value: String,
    address: Option<u64>,
    file_offset: Option<u64>,
}

pub(crate) fn analyze(
    bytes: &[u8],
    format: &FormatReport,
    architecture: Option<&str>,
    sections: &[SectionRecord],
    imports: &[SymbolRecord],
    exports: &[SymbolRecord],
    strings: &[ExtractedString],
) -> CodeAnalysisReport {
    let capabilities_without_code = capability_features(imports, strings, &[]);
    let Some(bitness) = x86_bitness(format, architecture) else {
        return CodeAnalysisReport {
            disassembly_supported: false,
            architecture: architecture.map(str::to_owned),
            reason: Some("Disassembly currently supports x86 and x86-64 binaries.".into()),
            functions: Vec::new(),
            capabilities: match_capabilities(&capabilities_without_code),
            stats: empty_stats(sections),
        };
    };

    let (regions, executable_bytes, mut truncated) = executable_regions(bytes, sections);
    if regions.is_empty() {
        return CodeAnalysisReport {
            disassembly_supported: false,
            architecture: architecture.map(str::to_owned),
            reason: Some("No bounded executable section bytes were available.".into()),
            functions: Vec::new(),
            capabilities: match_capabilities(&capabilities_without_code),
            stats: CodeAnalysisStats {
                executable_sections: 0,
                executable_bytes: 0,
                decoded_instructions: 0,
                functions: 0,
                basic_blocks: 0,
                control_flow_edges: 0,
                truncated,
            },
        };
    }

    let mut seeds = BTreeMap::new();
    if let Some(entry) = entry_point(format)
        && contains_address(&regions, entry)
    {
        seeds.insert(
            entry,
            FunctionSeed {
                name: "entry_point".into(),
                source: "entry_point".into(),
            },
        );
    }
    for export in exports {
        let Some(address) = export.address else {
            continue;
        };
        if contains_address(&regions, address) {
            seeds.entry(address).or_insert_with(|| FunctionSeed {
                name: bounded_text(&export.name, 160),
                source: "export".into(),
            });
        }
    }
    if seeds.is_empty() {
        let region = &regions[0];
        seeds.insert(
            region.address,
            FunctionSeed {
                name: format!("section_{:x}", region.address),
                source: "executable_section".into(),
            },
        );
    }

    let mut queue: VecDeque<u64> = seeds.keys().copied().collect();
    let mut queued: BTreeSet<u64> = queue.iter().copied().collect();
    let mut processed = BTreeSet::new();
    let mut budget = DecodeBudget::default();
    let mut functions = Vec::new();

    while let Some(address) = queue.pop_front() {
        if processed.contains(&address) {
            continue;
        }
        if functions.len() >= MAX_FUNCTIONS || budget.instructions >= MAX_INSTRUCTIONS {
            budget.truncated = true;
            break;
        }
        let seed = seeds.get(&address).cloned().unwrap_or(FunctionSeed {
            name: format!("sub_{address:x}"),
            source: "direct_call".into(),
        });
        let Some(function) = decode_function(address, seed, bitness, &regions, &mut budget) else {
            processed.insert(address);
            continue;
        };
        for call in &function.calls {
            let Some(target) = call.target else {
                continue;
            };
            if contains_address(&regions, target) && queued.insert(target) {
                seeds.entry(target).or_insert_with(|| FunctionSeed {
                    name: format!("sub_{target:x}"),
                    source: "direct_call".into(),
                });
                queue.push_back(target);
            }
        }
        processed.insert(address);
        functions.push(function);
    }
    truncated |= budget.truncated || !queue.is_empty();
    functions.sort_by_key(|function| function.address);

    let instruction_features = functions
        .iter()
        .flat_map(|function| &function.blocks)
        .flat_map(|block| &block.instructions)
        .map(|instruction| Feature {
            kind: "instruction",
            normalized: instruction.mnemonic.to_ascii_lowercase(),
            value: instruction.text.clone(),
            address: Some(instruction.address),
            file_offset: Some(instruction.file_offset),
        })
        .collect::<Vec<_>>();
    let features = capability_features(imports, strings, &instruction_features);
    let capabilities = match_capabilities(&features);

    CodeAnalysisReport {
        disassembly_supported: true,
        architecture: Some(if bitness == 64 { "x86-64" } else { "x86" }.into()),
        reason: None,
        stats: CodeAnalysisStats {
            executable_sections: regions.len() as u32,
            executable_bytes: executable_bytes as u64,
            decoded_instructions: budget.instructions as u32,
            functions: functions.len() as u32,
            basic_blocks: budget.blocks as u32,
            control_flow_edges: budget.edges as u32,
            truncated,
        },
        functions,
        capabilities,
    }
}

fn empty_stats(sections: &[SectionRecord]) -> CodeAnalysisStats {
    CodeAnalysisStats {
        executable_sections: sections
            .iter()
            .filter(|section| section.permissions.contains('x'))
            .count() as u32,
        executable_bytes: 0,
        decoded_instructions: 0,
        functions: 0,
        basic_blocks: 0,
        control_flow_edges: 0,
        truncated: false,
    }
}

fn x86_bitness(format: &FormatReport, architecture: Option<&str>) -> Option<u32> {
    let architecture = architecture.unwrap_or_default().to_ascii_lowercase();
    let x86 = architecture.contains("x86")
        || architecture.contains("i386")
        || architecture.contains("i686")
        || architecture.contains("amd64");
    if !x86 {
        return None;
    }
    match format {
        FormatReport::Pe { bitness, .. } | FormatReport::Elf { bitness, .. } => {
            Some(u32::from(*bitness))
        }
        FormatReport::MachO { bitness, .. } => bitness.map(u32::from),
        _ => None,
    }
}

fn entry_point(format: &FormatReport) -> Option<u64> {
    match format {
        FormatReport::Pe { entry_point, .. } | FormatReport::Elf { entry_point, .. } => {
            Some(*entry_point)
        }
        FormatReport::MachO { entry_point, .. } => *entry_point,
        _ => None,
    }
}

fn executable_regions<'a>(
    bytes: &'a [u8],
    sections: &[SectionRecord],
) -> (Vec<CodeRegion<'a>>, usize, bool) {
    let mut remaining = MAX_CODE_BYTES;
    let mut total = 0usize;
    let mut truncated = false;
    let mut regions = Vec::new();
    for section in sections
        .iter()
        .filter(|section| section.permissions.contains('x'))
    {
        let Some(address) = section.virtual_address else {
            continue;
        };
        if address > MAX_SAFE_JS_ADDRESS {
            truncated = true;
            continue;
        }
        let Ok(offset) = usize::try_from(section.offset) else {
            truncated = true;
            continue;
        };
        if offset >= bytes.len() || remaining == 0 {
            truncated |= section.size > 0;
            continue;
        }
        let declared = usize::try_from(section.size).unwrap_or(usize::MAX);
        let available = bytes.len() - offset;
        let length = declared.min(available).min(remaining);
        if length == 0 {
            continue;
        }
        truncated |= length < declared;
        regions.push(CodeRegion {
            file_offset: offset,
            address,
            bytes: &bytes[offset..offset + length],
        });
        total += length;
        remaining -= length;
    }
    (regions, total, truncated)
}

fn contains_address(regions: &[CodeRegion<'_>], address: u64) -> bool {
    locate(regions, address).is_some()
}

fn locate<'a>(regions: &'a [CodeRegion<'a>], address: u64) -> Option<(&'a CodeRegion<'a>, usize)> {
    regions.iter().find_map(|region| {
        let relative = address.checked_sub(region.address)?;
        let offset = usize::try_from(relative).ok()?;
        (offset < region.bytes.len()).then_some((region, offset))
    })
}

fn file_offset(regions: &[CodeRegion<'_>], address: u64) -> Option<u64> {
    let (region, relative) = locate(regions, address)?;
    u64::try_from(region.file_offset.checked_add(relative)?).ok()
}

fn decode_function(
    address: u64,
    seed: FunctionSeed,
    bitness: u32,
    regions: &[CodeRegion<'_>],
    budget: &mut DecodeBudget,
) -> Option<StaticFunction> {
    let function_file_offset = file_offset(regions, address);
    let mut pending = VecDeque::from([address]);
    let mut pending_set = BTreeSet::from([address]);
    let mut visited = BTreeSet::new();
    let mut blocks = Vec::new();
    let mut edges = Vec::new();
    let mut calls = Vec::new();
    let function_start_budget = budget.instructions;

    while let Some(block_start) = pending.pop_front() {
        if visited.contains(&block_start) {
            continue;
        }
        if blocks.len() >= MAX_BLOCKS_PER_FUNCTION
            || budget.blocks >= MAX_BASIC_BLOCKS
            || budget.instructions >= MAX_INSTRUCTIONS
            || budget.instructions - function_start_budget >= MAX_INSTRUCTIONS_PER_FUNCTION
        {
            budget.truncated = true;
            break;
        }
        let Some(block_file_offset) = file_offset(regions, block_start) else {
            continue;
        };
        visited.insert(block_start);
        let mut current = block_start;
        let mut instructions = Vec::new();
        let mut end = block_start;

        for _ in 0..MAX_INSTRUCTIONS_PER_BLOCK {
            if current != block_start && pending_set.contains(&current) {
                push_edge(
                    &mut edges,
                    budget,
                    StaticControlFlowEdge {
                        from: block_start,
                        to: current,
                        kind: "fallthrough".into(),
                    },
                );
                break;
            }
            if budget.instructions >= MAX_INSTRUCTIONS
                || budget.instructions - function_start_budget >= MAX_INSTRUCTIONS_PER_FUNCTION
            {
                budget.truncated = true;
                break;
            }
            let Some((region, relative)) = locate(regions, current) else {
                break;
            };
            let available = &region.bytes[relative..];
            let mut decoder = Decoder::with_ip(bitness, available, current, DecoderOptions::NONE);
            let instruction = decoder.decode();
            if instruction.code() == Code::INVALID || instruction.len() == 0 {
                break;
            }
            let length = instruction.len().min(available.len());
            let next = instruction.next_ip();
            let target = direct_target(&instruction);
            let instruction_file_offset = (region.file_offset + relative) as u64;
            instructions.push(StaticInstruction {
                address: current,
                file_offset: instruction_file_offset,
                bytes: hex::encode(&available[..length]),
                text: bounded_text(&instruction.to_string(), 200),
                mnemonic: format!("{:?}", instruction.mnemonic()).to_ascii_lowercase(),
                branch_target: target,
            });
            budget.instructions += 1;
            end = next;

            match instruction.flow_control() {
                FlowControl::Next => current = next,
                FlowControl::Call | FlowControl::IndirectCall => {
                    calls.push(StaticCallTarget {
                        instruction_address: current,
                        target,
                        kind: if target.is_some() {
                            "direct"
                        } else {
                            "indirect"
                        }
                        .into(),
                    });
                    current = next;
                }
                FlowControl::ConditionalBranch => {
                    if let Some(target) = target
                        && contains_address(regions, target)
                    {
                        push_edge(
                            &mut edges,
                            budget,
                            StaticControlFlowEdge {
                                from: block_start,
                                to: target,
                                kind: "branch".into(),
                            },
                        );
                        queue_block(target, &mut pending, &mut pending_set, &visited);
                    }
                    if contains_address(regions, next) {
                        push_edge(
                            &mut edges,
                            budget,
                            StaticControlFlowEdge {
                                from: block_start,
                                to: next,
                                kind: "fallthrough".into(),
                            },
                        );
                        queue_block(next, &mut pending, &mut pending_set, &visited);
                    }
                    break;
                }
                FlowControl::UnconditionalBranch => {
                    if let Some(target) = target
                        && contains_address(regions, target)
                    {
                        push_edge(
                            &mut edges,
                            budget,
                            StaticControlFlowEdge {
                                from: block_start,
                                to: target,
                                kind: "jump".into(),
                            },
                        );
                        queue_block(target, &mut pending, &mut pending_set, &visited);
                    }
                    break;
                }
                FlowControl::IndirectBranch
                | FlowControl::Return
                | FlowControl::Interrupt
                | FlowControl::XbeginXabortXend
                | FlowControl::Exception => break,
            }
        }
        if instructions.len() >= MAX_INSTRUCTIONS_PER_BLOCK {
            budget.truncated = true;
        }

        if !instructions.is_empty() {
            budget.blocks += 1;
            blocks.push(StaticBasicBlock {
                start: block_start,
                end,
                file_offset: Some(block_file_offset),
                instructions,
            });
        }
    }

    if blocks.is_empty() {
        return None;
    }
    blocks.sort_by_key(|block| block.start);
    edges.sort_by_key(|edge| (edge.from, edge.to, edge.kind.clone()));
    edges.dedup_by(|left, right| {
        left.from == right.from && left.to == right.to && left.kind == right.kind
    });
    calls.sort_by_key(|call| (call.instruction_address, call.target));
    calls.dedup_by(|left, right| {
        left.instruction_address == right.instruction_address && left.target == right.target
    });
    Some(StaticFunction {
        address,
        file_offset: function_file_offset,
        name: seed.name,
        source: seed.source,
        blocks,
        edges,
        calls,
    })
}

fn queue_block(
    address: u64,
    pending: &mut VecDeque<u64>,
    pending_set: &mut BTreeSet<u64>,
    visited: &BTreeSet<u64>,
) {
    if !visited.contains(&address) && pending_set.insert(address) {
        pending.push_back(address);
    }
}

fn push_edge(
    edges: &mut Vec<StaticControlFlowEdge>,
    budget: &mut DecodeBudget,
    edge: StaticControlFlowEdge,
) {
    if budget.edges >= MAX_EDGES {
        budget.truncated = true;
        return;
    }
    budget.edges += 1;
    edges.push(edge);
}

fn direct_target(instruction: &iced_x86::Instruction) -> Option<u64> {
    matches!(
        instruction.op0_kind(),
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
    )
    .then(|| instruction.near_branch_target())
}

fn capability_features(
    imports: &[SymbolRecord],
    strings: &[ExtractedString],
    instructions: &[Feature],
) -> Vec<Feature> {
    let mut features = Vec::with_capacity(imports.len() + strings.len() + instructions.len());
    features.extend(imports.iter().map(|import| {
        let value = match import.module.as_deref() {
            Some(module) => format!("{module}!{}", import.name),
            None => import.name.clone(),
        };
        Feature {
            kind: "import",
            normalized: import.name.to_ascii_lowercase(),
            value: bounded_text(&value, 240),
            address: import.address,
            file_offset: None,
        }
    }));
    features.extend(strings.iter().map(|item| Feature {
        kind: "string",
        normalized: item.value.to_ascii_lowercase(),
        value: bounded_text(&item.value, 240),
        address: None,
        file_offset: Some(item.offset),
    }));
    features.extend_from_slice(instructions);
    features
}

fn match_capabilities(features: &[Feature]) -> Vec<CapabilityMatch> {
    let mut matches = Vec::new();
    add_any(
        &mut matches,
        features,
        CapabilityRule {
            id: "process-execution",
            name: "Execute a process or command",
            namespace: "execution/process",
            description: "References APIs or command material commonly used to start another process.",
            confidence: Confidence::High,
        },
        &[
            "import:winexec",
            "import:createprocess",
            "import:shellexecute",
            "import:=system",
            "import:=popen",
            "string:powershell",
            "string:cmd.exe",
            "string:/bin/sh",
        ],
    );
    add_any(
        &mut matches,
        features,
        CapabilityRule {
            id: "network-communication",
            name: "Communicate over a network",
            namespace: "communication/network",
            description: "References networking APIs, protocols, or remote destinations.",
            confidence: Confidence::Medium,
        },
        &[
            "import:wininet",
            "import:winhttp",
            "import:internetopen",
            "import:httpopenrequest",
            "import:wsastartup",
            "import:=socket",
            "import:=connect",
            "import:urldownloadtofile",
            "string:http://",
            "string:https://",
        ],
    );
    add_all_groups(
        &mut matches,
        features,
        CapabilityRule {
            id: "dynamic-api-resolution",
            name: "Resolve APIs dynamically",
            namespace: "load-code/resolve-api",
            description: "Combines module loading with runtime export lookup.",
            confidence: Confidence::High,
        },
        &[
            &["import:loadlibrary", "import:ldrloaddll"],
            &["import:getprocaddress", "import:ldrgetprocedureaddress"],
        ],
    );
    add_group_threshold(
        &mut matches,
        features,
        CapabilityRule {
            id: "process-injection",
            name: "Manipulate another process",
            namespace: "host-interaction/process-injection",
            description: "Combines multiple primitives associated with cross-process memory modification or execution.",
            confidence: Confidence::High,
        },
        &[
            &["import:openprocess"],
            &["import:virtualallocex", "import:ntallocatevirtualmemory"],
            &["import:writeprocessmemory", "import:ntwritevirtualmemory"],
            &[
                "import:createremotethread",
                "import:ntcreatethreadex",
                "import:queueuserapc",
            ],
        ],
        2,
    );
    add_any(
        &mut matches,
        features,
        CapabilityRule {
            id: "file-manipulation",
            name: "Create or modify files",
            namespace: "host-interaction/file-system",
            description: "References APIs that create, write, move, or delete files.",
            confidence: Confidence::Medium,
        },
        &[
            "import:createfile",
            "import:writefile",
            "import:deletefile",
            "import:movefile",
            "import:copyfile",
            "import:=fopen",
            "import:=fwrite",
            "import:=unlink",
        ],
    );
    add_any(
        &mut matches,
        features,
        CapabilityRule {
            id: "registry-modification",
            name: "Modify the Windows registry",
            namespace: "host-interaction/registry",
            description: "References APIs that create or modify registry keys and values.",
            confidence: Confidence::High,
        },
        &[
            "import:regsetvalue",
            "import:regcreatekey",
            "import:ntsetvaluekey",
            "string:hkey_",
            "string:hkcu\\",
            "string:hklm\\",
        ],
    );
    add_any(
        &mut matches,
        features,
        CapabilityRule {
            id: "memory-protection",
            name: "Change memory protections",
            namespace: "memory/protection",
            description: "References APIs used to make memory executable or otherwise change page protections.",
            confidence: Confidence::High,
        },
        &[
            "import:virtualprotect",
            "import:ntprotectvirtualmemory",
            "import:=mprotect",
        ],
    );
    add_any(
        &mut matches,
        features,
        CapabilityRule {
            id: "anti-analysis",
            name: "Inspect or evade the analysis environment",
            namespace: "anti-analysis/environment",
            description: "References debugger, timing, or processor-identification checks.",
            confidence: Confidence::Medium,
        },
        &[
            "import:isdebuggerpresent",
            "import:checkremotedebuggerpresent",
            "import:ntqueryinformationprocess",
            "import:queryperformancecounter",
            "instruction:=rdtsc",
            "instruction:=rdtscp",
            "instruction:=cpuid",
        ],
    );
    add_any(
        &mut matches,
        features,
        CapabilityRule {
            id: "system-discovery",
            name: "Discover host or user information",
            namespace: "discovery/system",
            description: "References APIs commonly used to enumerate the host, user, or running processes.",
            confidence: Confidence::Medium,
        },
        &[
            "import:getcomputername",
            "import:getusername",
            "import:enumprocesses",
            "import:createtoolhelp32snapshot",
            "import:process32first",
            "import:process32next",
            "import:=uname",
            "import:gethostname",
        ],
    );
    add_any(
        &mut matches,
        features,
        CapabilityRule {
            id: "credential-access",
            name: "Access credential material",
            namespace: "credential-access",
            description: "References credential, secret-decryption, or account-database material.",
            confidence: Confidence::High,
        },
        &[
            "import:credread",
            "import:cryptunprotectdata",
            "import:lsaretrieveprivatedata",
            "string:sam\\",
            "string:security\\policy\\secrets",
        ],
    );
    add_any(
        &mut matches,
        features,
        CapabilityRule {
            id: "cryptography",
            name: "Use cryptographic operations",
            namespace: "data-manipulation/cryptography",
            description: "References cryptographic providers, hashing, encryption, or decryption APIs.",
            confidence: Confidence::Medium,
        },
        &[
            "import:bcrypt",
            "import:cryptencrypt",
            "import:cryptdecrypt",
            "import:crypthashdata",
            "import:evp_encrypt",
            "import:evp_decrypt",
            "import:sha256",
            "import:aes_",
        ],
    );
    matches.sort_by(|left, right| {
        left.namespace
            .cmp(&right.namespace)
            .then(left.id.cmp(&right.id))
    });
    matches
}

struct CapabilityRule {
    id: &'static str,
    name: &'static str,
    namespace: &'static str,
    description: &'static str,
    confidence: Confidence,
}

fn add_any(
    matches: &mut Vec<CapabilityMatch>,
    features: &[Feature],
    rule: CapabilityRule,
    needles: &[&str],
) {
    let evidence = evidence_for(features, needles);
    if !evidence.is_empty() {
        matches.push(capability(rule, evidence));
    }
}

fn add_all_groups(
    matches: &mut Vec<CapabilityMatch>,
    features: &[Feature],
    rule: CapabilityRule,
    groups: &[&[&str]],
) {
    let mut evidence = Vec::new();
    for group in groups {
        let group_evidence = evidence_for(features, group);
        if group_evidence.is_empty() {
            return;
        }
        evidence.extend(group_evidence);
    }
    matches.push(capability(rule, bounded_evidence(evidence)));
}

fn add_group_threshold(
    matches: &mut Vec<CapabilityMatch>,
    features: &[Feature],
    rule: CapabilityRule,
    groups: &[&[&str]],
    threshold: usize,
) {
    let populated = groups
        .iter()
        .map(|group| evidence_for(features, group))
        .filter(|evidence| !evidence.is_empty())
        .collect::<Vec<_>>();
    if populated.len() >= threshold {
        matches.push(capability(
            rule,
            bounded_evidence(populated.into_iter().flatten().collect()),
        ));
    }
}

fn evidence_for(features: &[Feature], needles: &[&str]) -> Vec<CapabilityEvidence> {
    bounded_evidence(
        features
            .iter()
            .filter(|feature| {
                needles
                    .iter()
                    .any(|selector| feature_matches(feature, selector))
            })
            .map(|feature| CapabilityEvidence {
                kind: feature.kind.into(),
                value: feature.value.clone(),
                address: feature.address,
                file_offset: feature.file_offset,
            })
            .collect(),
    )
}

fn feature_matches(feature: &Feature, selector: &str) -> bool {
    let (kind, pattern) = selector.split_once(':').unwrap_or(("any", selector));
    if kind != "any" && feature.kind != kind {
        return false;
    }
    if let Some(exact) = pattern.strip_prefix('=') {
        feature.normalized == exact
    } else {
        feature.normalized.contains(pattern)
    }
}

fn bounded_evidence(mut evidence: Vec<CapabilityEvidence>) -> Vec<CapabilityEvidence> {
    evidence.sort_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then(left.value.cmp(&right.value))
            .then(left.address.cmp(&right.address))
    });
    evidence.dedup_by(|left, right| {
        left.kind == right.kind
            && left.value == right.value
            && left.address == right.address
            && left.file_offset == right.file_offset
    });
    evidence.truncate(MAX_CAPABILITY_EVIDENCE);
    evidence
}

fn capability(rule: CapabilityRule, evidence: Vec<CapabilityEvidence>) -> CapabilityMatch {
    let confidence = if rule.confidence == Confidence::High
        && evidence.iter().all(|item| item.kind == "string")
    {
        Confidence::Medium
    } else {
        rule.confidence
    };
    CapabilityMatch {
        id: rule.id.into(),
        name: rule.name.into(),
        namespace: rule.namespace.into(),
        description: rule.description.into(),
        confidence,
        evidence,
    }
}

fn bounded_text(value: &str, maximum: usize) -> String {
    value.chars().take(maximum).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn correlates_process_injection_only_after_two_primitive_groups() {
        let one = vec![feature("OpenProcess")];
        assert!(
            match_capabilities(&one)
                .iter()
                .all(|item| item.id != "process-injection")
        );
        let two = vec![feature("OpenProcess"), feature("WriteProcessMemory")];
        assert!(
            match_capabilities(&two)
                .iter()
                .any(|item| item.id == "process-injection")
        );
    }

    #[test]
    fn requires_module_load_and_export_lookup_for_dynamic_resolution() {
        let partial = vec![feature("GetProcAddress")];
        assert!(
            match_capabilities(&partial)
                .iter()
                .all(|item| item.id != "dynamic-api-resolution")
        );
        let complete = vec![feature("LoadLibraryA"), feature("GetProcAddress")];
        assert!(
            match_capabilities(&complete)
                .iter()
                .any(|item| item.id == "dynamic-api-resolution")
        );
    }

    #[test]
    fn does_not_treat_generic_system_text_as_process_execution() {
        let mut text = feature("SYSTEMROOT");
        text.kind = "string";
        assert!(
            match_capabilities(&[text])
                .iter()
                .all(|item| item.id != "process-execution")
        );
    }

    #[test]
    fn downgrades_string_only_high_confidence_rules() {
        let mut text = feature("powershell.exe");
        text.kind = "string";
        let matched = match_capabilities(&[text]);
        let process = matched
            .iter()
            .find(|item| item.id == "process-execution")
            .expect("process execution capability");
        assert_eq!(process.confidence, Confidence::Medium);
    }

    fn feature(value: &str) -> Feature {
        Feature {
            kind: "import",
            normalized: value.to_ascii_lowercase(),
            value: value.into(),
            address: None,
            file_offset: None,
        }
    }
}
