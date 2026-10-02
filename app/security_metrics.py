"""
Framework-independent security metrics derived from canonical events.

Metrics observe normalized SecurityEvent records. They do not establish
or influence authentication, authorization, tenant, session, workflow,
execution-attempt, or provider authority.

Only explicitly bounded canonical enum fields may become labels.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from enum import Enum
from threading import Lock
from types import MappingProxyType
from typing import Mapping

from app.security_observability import (
    SecurityEvent,
    SecurityEventType,
    SecurityOutcome,
    SecurityReasonCode,
    SecuritySeverity,
    SecuritySourceComponent,
)


class SecurityMetricValidationError(ValueError):
    """
    Raised when a security metric observation violates the bounded
    canonical metrics contract.
    """


class SecurityMetricName(str, Enum):
    """
    Canonical v1 security counters.

    Additional metrics require an explicit schema decision rather than
    arbitrary caller-defined names or labels.
    """

    SECURITY_EVENTS_TOTAL = (
        "security_events_total"
    )

    SECURITY_DENIALS_TOTAL = (
        "security_denials_total"
    )

    SECURITY_REVIEW_REQUIRED_TOTAL = (
        "security_review_required_total"
    )


NO_REASON_LABEL = "none"


PROHIBITED_SECURITY_METRIC_LABELS = frozenset(
    {
        "event_id",
        "request_id",
        "principal_ref",
        "tenant_id",
        "session_ref",
        "workflow_id",
        "execution_attempt_ref",
        "provider_correlation_id",
        "execution_attempt_id",
        "session_id",
        "principal_id",
        "username",
        "email",
        "ticket_id",
        "ticket_number",
        "sys_id",
        "exception",
        "exception_text",
        "provider_response",
    }
)


SECURITY_METRIC_LABEL_SCHEMA = MappingProxyType(
    {
        SecurityMetricName.SECURITY_EVENTS_TOTAL: (
            "event_type",
            "severity",
            "outcome",
            "source_component",
        ),
        SecurityMetricName.SECURITY_DENIALS_TOTAL: (
            "event_type",
            "reason_code",
            "source_component",
        ),
        SecurityMetricName.SECURITY_REVIEW_REQUIRED_TOTAL: (
            "event_type",
            "reason_code",
            "source_component",
        ),
    }
)


@dataclass(
    frozen=True,
    slots=True,
)
class SecurityMetricSample:
    """
    One deterministic counter sample.

    labels is an ordered tuple so callers cannot mutate internal registry
    state and snapshot ordering remains deterministic.
    """

    name: SecurityMetricName

    labels: tuple[
        tuple[
            str,
            str,
        ],
        ...,
    ]

    value: int


    def to_dict(
        self,
    ) -> dict[
        str,
        object,
    ]:
        return {
            "name":
                self.name.value,
            "labels":
                dict(
                    self.labels
                ),
            "value":
                self.value,
        }


def security_metric_series_bounds(
) -> Mapping[
    SecurityMetricName,
    int,
]:
    """
    Return the theoretical maximum label-series count for each metric.

    The bounds are derived only from finite canonical enum vocabularies.
    The additional +1 reason-code value is the fixed NO_REASON_LABEL.
    """

    reason_cardinality = (
        len(
            SecurityReasonCode
        )
        + 1
    )


    return MappingProxyType(
        {
            SecurityMetricName.SECURITY_EVENTS_TOTAL:
                (
                    len(
                        SecurityEventType
                    )
                    * len(
                        SecuritySeverity
                    )
                    * len(
                        SecurityOutcome
                    )
                    * len(
                        SecuritySourceComponent
                    )
                ),

            SecurityMetricName.SECURITY_DENIALS_TOTAL:
                (
                    len(
                        SecurityEventType
                    )
                    * reason_cardinality
                    * len(
                        SecuritySourceComponent
                    )
                ),

            SecurityMetricName.SECURITY_REVIEW_REQUIRED_TOTAL:
                (
                    len(
                        SecurityEventType
                    )
                    * reason_cardinality
                    * len(
                        SecuritySourceComponent
                    )
                ),
        }
    )


class SecurityMetricsRegistry:
    """
    Thread-safe process-local registry for canonical security counters.

    The registry intentionally exposes no generic arbitrary-label API.
    Callers provide only a validated SecurityEvent. Metric names and
    label schemas are controlled entirely by this module.
    """

    def __init__(
        self,
    ) -> None:
        self._counts: Counter[
            tuple[
                SecurityMetricName,
                tuple[
                    tuple[
                        str,
                        str,
                    ],
                    ...,
                ],
            ]
        ] = Counter()

        self._lock = Lock()


    def observe(
        self,
        event: SecurityEvent,
    ) -> None:
        """
        Observe one already-normalized canonical security event.

        Metrics are derived exclusively from bounded event enums. No
        correlation identifier or arbitrary event detail becomes a label.
        """

        if not isinstance(
            event,
            SecurityEvent,
        ):
            raise SecurityMetricValidationError(
                "Security metrics require "
                "a canonical SecurityEvent."
            )


        event_type = (
            event.event_type.value
        )

        severity = (
            event.severity.value
        )

        outcome = (
            event.outcome.value
        )

        source_component = (
            event.source_component.value
        )

        reason_code = (
            event.reason_code.value
            if event.reason_code
            is not None
            else NO_REASON_LABEL
        )


        with self._lock:

            self._increment_locked(
                SecurityMetricName
                .SECURITY_EVENTS_TOTAL,
                {
                    "event_type":
                        event_type,
                    "severity":
                        severity,
                    "outcome":
                        outcome,
                    "source_component":
                        source_component,
                },
            )


            if (
                outcome
                == "denied"
            ):

                self._increment_locked(
                    SecurityMetricName
                    .SECURITY_DENIALS_TOTAL,
                    {
                        "event_type":
                            event_type,
                        "reason_code":
                            reason_code,
                        "source_component":
                            source_component,
                    },
                )


            if (
                outcome
                == "review_required"
            ):

                self._increment_locked(
                    SecurityMetricName
                    .SECURITY_REVIEW_REQUIRED_TOTAL,
                    {
                        "event_type":
                            event_type,
                        "reason_code":
                            reason_code,
                        "source_component":
                            source_component,
                    },
                )


    def _increment_locked(
        self,
        metric_name: SecurityMetricName,
        labels: Mapping[
            str,
            str,
        ],
    ) -> None:
        """
        Increment one metric after exact schema/cardinality validation.

        Caller must hold self._lock.
        """

        if not isinstance(
            metric_name,
            SecurityMetricName,
        ):
            raise SecurityMetricValidationError(
                "Metric name is not part of "
                "the canonical security metrics vocabulary."
            )


        expected_schema = (
            SECURITY_METRIC_LABEL_SCHEMA[
                metric_name
            ]
        )


        if (
            set(
                labels
            )
            != set(
                expected_schema
            )
        ):
            raise SecurityMetricValidationError(
                "Security metric labels do not "
                "match the canonical schema."
            )


        if (
            set(
                labels
            )
            & PROHIBITED_SECURITY_METRIC_LABELS
        ):
            raise SecurityMetricValidationError(
                "Security metric attempted to use "
                "a prohibited high-cardinality label."
            )


        ordered_labels = []


        for name in expected_schema:

            value = (
                labels[
                    name
                ]
            )


            if not isinstance(
                value,
                str,
            ):
                raise SecurityMetricValidationError(
                    "Security metric label values "
                    "must be strings."
                )


            if (
                not value
                or value
                != value.strip()
            ):
                raise SecurityMetricValidationError(
                    "Security metric label values "
                    "must be normalized non-blank strings."
                )


            if len(
                value
            ) > 128:
                raise SecurityMetricValidationError(
                    "Security metric label value "
                    "exceeds the bounded profile."
                )


            ordered_labels.append(
                (
                    name,
                    value,
                )
            )


        key = (
            metric_name,
            tuple(
                ordered_labels
            ),
        )


        self._counts[
            key
        ] += 1


    def snapshot(
        self,
    ) -> tuple[
        SecurityMetricSample,
        ...,
    ]:
        """
        Return an immutable deterministic view of current counter values.
        """

        with self._lock:

            samples = [
                SecurityMetricSample(
                    name=
                        metric_name,
                    labels=
                        labels,
                    value=
                        count,
                )
                for (
                    metric_name,
                    labels,
                ), count
                in self._counts.items()
            ]


        return tuple(
            sorted(
                samples,
                key=lambda sample:
                    (
                        sample.name.value,
                        sample.labels,
                    ),
            )
        )


# Process-local observability state only.
#
# This registry has no role in authentication, authorization, tenant
# selection, session validity, workflow transitions, exact-attempt
# authority, or provider execution.
_PROCESS_SECURITY_METRICS_REGISTRY = (
    SecurityMetricsRegistry()
)


def get_process_security_metrics_registry(
) -> SecurityMetricsRegistry:
    """
    Return the process-local canonical security metrics registry.

    The explicit getter keeps process metrics lifecycle separate from
    security authority and gives integration/export code one narrow
    access boundary.
    """

    return (
        _PROCESS_SECURITY_METRICS_REGISTRY
    )


def _reset_process_security_metrics_registry_for_tests(
) -> SecurityMetricsRegistry:
    """
    Replace process metrics state for isolated tests.

    This private helper changes observability state only.
    """

    global _PROCESS_SECURITY_METRICS_REGISTRY

    _PROCESS_SECURITY_METRICS_REGISTRY = (
        SecurityMetricsRegistry()
    )

    return (
        _PROCESS_SECURITY_METRICS_REGISTRY
    )
