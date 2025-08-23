# modules/compliance_scoring.py

def score_compliance(detected_pii, config_rules):
    total_rules = 3
    passed_rules = 0
    violations = []

    # Rule 1: Max number of allowed PII types
    max_allowed_pii = config_rules.get("max_pii_fields", 3)
    pii_types_detected = set(item["pattern"] for item in detected_pii)
    if len(pii_types_detected) <= max_allowed_pii:
        passed_rules += 1
    else:
        violations.append(f"Too many PII types detected: {len(pii_types_detected)} > allowed {max_allowed_pii}")

    # Rule 2: Only allow specific PII types
    allowed_types = config_rules.get("allowed_pii_types", [])
    disallowed = [pii for pii in pii_types_detected if pii not in allowed_types]
    if not disallowed:
        passed_rules += 1
    else:
        for pii in disallowed:
            violations.append(f"Disallowed PII type detected: {pii}")

    # Rule 3: Anonymization required
    if config_rules.get("anonymization_required", False):
        violations.append("Anonymization not verified.")  # Future version can validate this
    else:
        passed_rules += 1

    score = round((passed_rules / total_rules) * 100, 2)
    return score, violations
