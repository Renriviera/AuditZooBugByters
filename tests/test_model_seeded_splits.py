"""Tests for model-seeded sweep dataset selection and splitting."""

from __future__ import annotations

import pytest

from splitEvaluations.common import (
    build_split_metadata,
    eligible_dataset,
    select_dataset_subset,
    split_train_validate,
)


def _dataset(n: int) -> list[dict]:
    return [
        {
            "cve_id": f"CVE-2099-{idx:04d}",
            "vulnerable_lines": [idx],
        }
        for idx in range(1, n + 1)
    ]


def test_select_dataset_subset_is_deterministic() -> None:
    dataset = _dataset(40)
    first = select_dataset_subset(dataset, 10, seed=235711)
    second = select_dataset_subset(dataset, "10", seed=235711)
    assert [c["cve_id"] for c in first] == [c["cve_id"] for c in second]
    assert len(first) == 10


@pytest.mark.parametrize(
    ("size", "expected_train", "expected_validate"),
    [(10, 3, 7), (30, 8, 22), ("full", 25, 75)],
)
def test_split_train_validate_uses_ceil_quarter(
    size: int | str, expected_train: int, expected_validate: int
) -> None:
    selected = select_dataset_subset(_dataset(100), size, seed=235711)
    train, validate = split_train_validate(selected, 0.25, seed=235711)
    assert len(train) == expected_train
    assert len(validate) == expected_validate
    assert {c["cve_id"] for c in train}.isdisjoint(
        {c["cve_id"] for c in validate}
    )


def test_eligible_dataset_applies_skip_and_empty_gt() -> None:
    dataset = _dataset(3)
    dataset[1]["vulnerable_lines"] = []
    eligible = eligible_dataset(
        dataset, skip_cves=["CVE-2099-0003"], skip_empty_gt=True
    )
    assert [c["cve_id"] for c in eligible] == ["CVE-2099-0001"]


def test_build_split_metadata_records_cve_ids() -> None:
    selected = _dataset(10)
    train, validate = split_train_validate(selected, 0.25, seed=235711)
    metadata = build_split_metadata(
        selected_dataset=selected,
        training_dataset=train,
        validation_dataset=validate,
        dataset_size=10,
        train_fraction=0.25,
        seed=235711,
    )
    assert metadata["selected_count"] == 10
    assert metadata["training_count"] == 3
    assert metadata["validation_count"] == 7
    assert len(metadata["training_cves"]) == 3
