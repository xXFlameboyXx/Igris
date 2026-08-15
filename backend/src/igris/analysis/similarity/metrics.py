"""Phase 10 deterministic multi-level similarity metrics and comparison engine."""

import math

from igris.schemas.similarity import (
    NormalizedSampleFeatures,
    SampleSimilarityMatch,
    SimilarityConfidence,
    SimilarityHypothesis,
)


def jaccard_similarity(set_a: set[str], set_b: set[str]) -> float:
    """Compute Jaccard similarity between two string token sets."""
    if not set_a and not set_b:
        return 1.0
    union_len = len(set_a | set_b)
    if union_len == 0:
        return 1.0
    return round(len(set_a & set_b) / union_len, 4)


def cosine_similarity_counts(dict_a: dict[str, int], dict_b: dict[str, int]) -> float:
    """Compute cosine similarity between two frequency counter dictionaries."""
    if not dict_a or not dict_b:
        return 0.0

    all_keys = set(dict_a.keys()) | set(dict_b.keys())
    dot_product = sum(dict_a.get(k, 0) * dict_b.get(k, 0) for k in all_keys)
    norm_a = math.sqrt(sum(v * v for v in dict_a.values()))
    norm_b = math.sqrt(sum(v * v for v in dict_b.values()))

    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    return round(dot_product / (norm_a * norm_b), 4)


def calculate_file_similarity(
    f1: NormalizedSampleFeatures, f2: NormalizedSampleFeatures
) -> tuple[float, list[str], list[str], list[str]]:
    """Compute normalized file-level similarity across format, APIs, strings, and sections."""
    shared: list[str] = []
    diffs: list[str] = []
    categories: list[str] = []

    # 1. Format match
    format_score = 0.0
    if f1.detected_format and f2.detected_format:
        if f1.detected_format == f2.detected_format:
            format_score = 1.0
            shared.append(f"Matching file format: {f1.detected_format.upper()}")
        else:
            format_score = 0.0
            diffs.append(
                f"Format mismatch: {f1.detected_format.upper()} vs {f2.detected_format.upper()}"
            )
    else:
        format_score = 0.5  # Neutral when format detection unavailable

    # 2. Imported API similarity
    apis1 = set(f1.imported_apis)
    apis2 = set(f2.imported_apis)
    api_score = jaccard_similarity(apis1, apis2)
    if apis1 or apis2:
        shared_apis = sorted(apis1 & apis2)
        if shared_apis:
            categories.append("apis")
            api_preview = ", ".join(shared_apis[:4])
            shared.append(f"Shared {len(shared_apis)} imported API(s): {api_preview}")
        diff_apis = sorted(apis1 ^ apis2)
        if diff_apis:
            diffs.append(f"Distinct {len(diff_apis)} imported API(s)")

    # 3. String similarity
    str1 = set(f1.interesting_strings)
    str2 = set(f2.interesting_strings)
    str_score = jaccard_similarity(str1, str2)
    if str1 or str2:
        shared_strs = sorted(str1 & str2)
        if shared_strs:
            categories.append("strings")
            shared.append(f"Shared {len(shared_strs)} indicator string(s)")
        diff_strs = sorted(str1 ^ str2)
        if diff_strs:
            diffs.append(f"Distinct {len(diff_strs)} indicator string(s)")

    # 4. Section structure similarity
    sec1_names = {s.name for s in f1.sections}
    sec2_names = {s.name for s in f2.sections}
    section_score = 0.0
    if sec1_names or sec2_names:
        sec_name_score = jaccard_similarity(sec1_names, sec2_names)
        shared_sec_names = sorted(sec1_names & sec2_names)
        if shared_sec_names:
            categories.append("sections")
            shared.append(f"Shared section(s): {', '.join(shared_sec_names)}")

        # Entropy delta on shared sections
        sec1_map = {s.name: s for s in f1.sections}
        sec2_map = {s.name: s for s in f2.sections}
        entropy_scores: list[float] = []
        for name in shared_sec_names:
            ent_diff = abs(sec1_map[name].entropy - sec2_map[name].entropy)
            # Difference <= 0.5 entropy is very similar
            ent_sim = max(0.0, 1.0 - (ent_diff / 4.0))
            entropy_scores.append(ent_sim)

        avg_ent_score = sum(entropy_scores) / len(entropy_scores) if entropy_scores else 0.0
        section_score = round(0.5 * sec_name_score + 0.5 * avg_ent_score, 4)

    # Weighted aggregation for file level:
    # If APIs present: APIs (40%), Sections (30%), Strings (20%), Format (10%)
    if apis1 or apis2:
        weights = (0.40, 0.30, 0.20, 0.10)
        file_sim = (
            weights[0] * api_score
            + weights[1] * section_score
            + weights[2] * str_score
            + weights[3] * format_score
        )
    else:
        # If no APIs: Sections (50%), Strings (30%), Format (20%)
        file_sim = 0.50 * section_score + 0.30 * str_score + 0.20 * format_score

    return round(min(max(file_sim, 0.0), 1.0), 4), categories, shared, diffs


def calculate_code_similarity(
    f1: NormalizedSampleFeatures, f2: NormalizedSampleFeatures
) -> tuple[float, list[str], list[str], list[str]]:
    """Compute code-level similarity across recovered functions and opcode distributions."""
    shared: list[str] = []
    diffs: list[str] = []
    categories: list[str] = []

    if not f1.has_reverse or not f2.has_reverse:
        if not f1.has_reverse and not f2.has_reverse:
            return 0.0, [], [], ["Reverse engineering unobserved for both samples"]
        return 0.0, [], [], ["Reverse engineering unavailable for one sample"]

    # 1. Function counts & signatures
    fn1_set = set(f1.function_signatures)
    fn2_set = set(f2.function_signatures)
    if not fn1_set and not fn2_set:
        fn_sig_score = 1.0 if f1.function_count == f2.function_count else 0.0
    else:
        fn_sig_score = jaccard_similarity(fn1_set, fn2_set)

    if f1.function_count > 0 and f2.function_count > 0:
        fn_count_ratio = min(f1.function_count, f2.function_count) / max(
            f1.function_count, f2.function_count
        )
    else:
        fn_count_ratio = 1.0 if f1.function_count == f2.function_count else 0.0

    fn_score = 0.5 * fn_sig_score + 0.5 * fn_count_ratio
    if fn_score >= 0.5:
        categories.append("functions")
        shared.append(f"Function structural alignment: {round(fn_score * 100)}%")
    else:
        diffs.append(f"Function count disparity: {f1.function_count} vs {f2.function_count}")

    # 2. Opcode / mnemonic distribution
    op_score = cosine_similarity_counts(f1.opcode_distribution, f2.opcode_distribution)
    if op_score >= 0.6:
        categories.append("opcodes")
        shared.append(f"Opcode mnemonic distribution similarity: {round(op_score * 100)}%")
    elif op_score > 0.0:
        diffs.append(f"Opcode distribution divergence: {round((1.0 - op_score) * 100)}%")

    # Weighted code similarity: Function structure (45%), Opcode profile (55%)
    code_sim = 0.45 * fn_score + 0.55 * op_score
    return round(min(max(code_sim, 0.0), 1.0), 4), categories, shared, diffs


def calculate_behavior_similarity(
    f1: NormalizedSampleFeatures, f2: NormalizedSampleFeatures
) -> tuple[float | None, list[str], list[str], list[str]]:
    """Compute behavioral similarity across processes, registry keys, network, and mutexes."""
    if not f1.has_behavior or not f2.has_behavior:
        return None, [], [], ["Behavioral telemetry unavailable for one or both samples"]

    shared: list[str] = []
    diffs: list[str] = []
    categories: list[str] = []

    # 1. Process execution
    procs1 = set(f1.behavior_processes)
    procs2 = set(f2.behavior_processes)
    proc_score = jaccard_similarity(procs1, procs2)
    shared_procs = sorted(procs1 & procs2)
    if shared_procs:
        categories.append("behavior")
        shared.append(f"Shared spawned processes: {', '.join(shared_procs)}")

    # 2. Registry operations
    regs1 = set(f1.behavior_registry_keys)
    regs2 = set(f2.behavior_registry_keys)
    reg_score = jaccard_similarity(regs1, regs2)
    shared_regs = sorted(regs1 & regs2)
    if shared_regs:
        shared.append(f"Shared {len(shared_regs)} registry modification key(s)")

    # 3. Network destinations
    nets1 = set(f1.behavior_network_targets)
    nets2 = set(f2.behavior_network_targets)
    net_score = jaccard_similarity(nets1, nets2)
    shared_nets = sorted(nets1 & nets2)
    if shared_nets:
        shared.append(f"Shared network target(s): {', '.join(shared_nets)}")

    # 4. Mutex objects
    muts1 = set(f1.behavior_mutexes)
    muts2 = set(f2.behavior_mutexes)
    mut_score = jaccard_similarity(muts1, muts2)
    shared_muts = sorted(muts1 & muts2)
    if shared_muts:
        shared.append(f"Shared synchronization mutex(es): {', '.join(shared_muts)}")

    # Weighted behavioral similarity: Processes (30%), Registry (30%), Network (25%), Mutexes (15%)
    beh_sim = 0.30 * proc_score + 0.30 * reg_score + 0.25 * net_score + 0.15 * mut_score
    return round(min(max(beh_sim, 0.0), 1.0), 4), categories, shared, diffs


def compare_samples(
    query_features: NormalizedSampleFeatures,
    candidate_features: NormalizedSampleFeatures,
    target_filename: str = "unknown",
) -> SampleSimilarityMatch:
    """Compare a query sample against a candidate sample producing explainable metrics."""
    file_sim, file_cats, file_shared, file_diffs = calculate_file_similarity(
        query_features, candidate_features
    )
    code_sim, code_cats, code_shared, code_diffs = calculate_code_similarity(
        query_features, candidate_features
    )
    beh_sim, beh_cats, beh_shared, beh_diffs = calculate_behavior_similarity(
        query_features, candidate_features
    )

    all_categories = sorted(set(file_cats + code_cats + beh_cats))
    shared_indicators = file_shared + code_shared + beh_shared
    divergent_indicators = file_diffs + code_diffs + beh_diffs

    # Adaptive overall weighting based on available analysis layers
    available_layers = 1  # File level is always present
    if query_features.has_reverse and candidate_features.has_reverse:
        available_layers += 1
    if beh_sim is not None:
        available_layers += 1

    if query_features.has_reverse and candidate_features.has_reverse and beh_sim is not None:
        # All three layers: File (40%), Code (35%), Behavior (25%)
        overall = 0.40 * file_sim + 0.35 * code_sim + 0.25 * beh_sim
    elif query_features.has_reverse and candidate_features.has_reverse:
        # Static + Reverse: File (55%), Code (45%)
        overall = 0.55 * file_sim + 0.45 * code_sim
    elif beh_sim is not None:
        # Static + Behavior: File (60%), Behavior (40%)
        overall = 0.60 * file_sim + 0.40 * beh_sim
    else:
        # File-only
        overall = file_sim

    overall = round(min(max(overall, 0.0), 1.0), 4)

    if overall >= 0.70:
        hypothesis = SimilarityHypothesis.POSSIBLE_RELATED_CLUSTER
    else:
        hypothesis = SimilarityHypothesis.UNRELATED

    if available_layers >= 3 or overall >= 0.95:
        confidence = SimilarityConfidence.HIGH
    elif available_layers == 2 or overall >= 0.75:
        confidence = SimilarityConfidence.MEDIUM
    else:
        confidence = SimilarityConfidence.LOW

    beh_str = f"{round(beh_sim * 100)}%" if beh_sim is not None else "N/A"
    explanation = (
        f"Compared across {len(all_categories)} matching feature category(ies) "
        f"yielding {round(overall * 100)}% overall similarity (File: {round(file_sim * 100)}%, "
        f"Code: {round(code_sim * 100)}%, Behavior: {beh_str})."
    )

    return SampleSimilarityMatch(
        target_sample_id=candidate_features.sample_id,
        target_sha256=candidate_features.sha256,
        target_filename=target_filename,
        overall_similarity=overall,
        file_similarity=file_sim,
        code_similarity=code_sim,
        behavior_similarity=beh_sim,
        matching_feature_categories=all_categories,
        shared_indicators=shared_indicators,
        differences=divergent_indicators,
        hypothesis=hypothesis,
        confidence=confidence,
        explanation=explanation,
    )
