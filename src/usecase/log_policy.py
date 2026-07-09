import json
import logging
from dataclasses import dataclass

from config.config import get_config
from entities.MCPContext import MCPContext

logger = logging.getLogger(__name__)

ALL_DATASETS = "*"


class DatasetAuthorizationError(PermissionError):
    """Raised when a principal is not allowed to query a dataset."""


@dataclass(frozen=True)
class DatasetPolicyDecision:
    allowed: bool
    principal_id: str
    dataset: str
    matched_group: str | None = None
    allowed_datasets: tuple[str, ...] = ()
    reason: str = ""


def _parse_dataset_policy(raw_policy: str) -> dict[str, tuple[str, ...]]:
    try:
        parsed = json.loads(raw_policy or "{}")
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid LOG_SEARCH_DATASET_POLICY JSON: {e}") from e

    if not isinstance(parsed, dict):
        raise ValueError("LOG_SEARCH_DATASET_POLICY must be a JSON object mapping groups to datasets")

    policy: dict[str, tuple[str, ...]] = {}
    for group, datasets in parsed.items():
        if isinstance(datasets, str):
            dataset_values = (datasets,)
        elif isinstance(datasets, list) and all(isinstance(dataset, str) for dataset in datasets):
            dataset_values = tuple(datasets)
        else:
            raise ValueError(f"Dataset policy for group {group} must be a string or list of strings")

        policy[str(group)] = tuple(dataset.strip() for dataset in dataset_values if dataset.strip())

    return policy


def get_dataset_policy() -> dict[str, tuple[str, ...]]:
    return _parse_dataset_policy(get_config().log_search_dataset_policy)


def authorize_dataset(context: MCPContext, dataset: str) -> DatasetPolicyDecision:
    policy = get_dataset_policy()
    principal_groups = tuple(context.groups or ())

    for group in principal_groups:
        allowed_datasets = policy.get(group)
        if not allowed_datasets:
            continue

        if ALL_DATASETS in allowed_datasets or dataset in allowed_datasets:
            return DatasetPolicyDecision(
                allowed=True,
                principal_id=context.principal_id,
                dataset=dataset,
                matched_group=group,
                allowed_datasets=allowed_datasets,
                reason="dataset allowed by group policy",
            )

    allowed_for_groups = tuple(sorted({dataset_name for group in principal_groups for dataset_name in policy.get(group, ())}))
    return DatasetPolicyDecision(
        allowed=False,
        principal_id=context.principal_id,
        dataset=dataset,
        allowed_datasets=allowed_for_groups,
        reason="dataset is not allowed for principal groups",
    )


def ensure_dataset_authorized(context: MCPContext, dataset: str) -> DatasetPolicyDecision:
    decision = authorize_dataset(context, dataset)
    if not decision.allowed:
        logger.info(
            "Denied log search for principal %s on dataset %s; allowed datasets: %s",
            decision.principal_id,
            dataset,
            ", ".join(decision.allowed_datasets) or "<none>",
        )
        raise DatasetAuthorizationError(
            f"Principal {decision.principal_id} is not allowed to query dataset {dataset}"
        )
    return decision
