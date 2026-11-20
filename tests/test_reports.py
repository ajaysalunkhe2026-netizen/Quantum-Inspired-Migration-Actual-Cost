from pqtls.report import compare_values
from pqtls.schema import EvidenceDocument

def test_comparison_is_calculated():
    assert compare_values(10, 15) == {
        "baseline": 10, "candidate": 15, "delta": 5, "label": "Calculated"
    }

def test_empty_evidence_document():
    assert EvidenceDocument(records=[]).records == []
