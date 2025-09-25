"""
Shared Splunk query definitions for SOC QA Agent.

Provides a macro-based Enterprise Security notable events query with
configurable earliest/latest time bounds.
"""

# Default time bounds
DEFAULT_EARLIEST = "-1h"
DEFAULT_LATEST = "now"

# Macro-based ES notable query (no leading pipe; suitable after `search`)
_NOTABLE_PIPELINE = (
<<<<<<< HEAD
    "`notable` "
    "| `get_current_status` "
    "| search search_name!=*HSDE* search_name!=*ffreactor* status_group=\"Closed\" "
=======
    "`notable` | `get_current_status` "
    "| search search_name!=*HSDE* search_name!=*ffreactor* "
>>>>>>> 01b0fb7 (major update 13)
    "| `get_owner` "
    "| where owner != \"unassigned\" "
    "| rename owner_realname AS \"analyst\", search_name as alert_title "
    "| `get_notable_disposition` "
    "| eval `get_event_id_meval`, rule_id=event_id "
    "| eventstats first(_time) as created_time, max(review_time) as closed_time by rule_id "
    "| rename annotations.* as annotations_* "
<<<<<<< HEAD
    "| eval open_duration=round(closed_time - created_time, 0) "
    "| eval escalation_status=if(disposition_label=\"True Positive - Escalated\",\"Escalated\",\"Not Escalated\") "
    "| table * "
    "| sort - closed_time "
    "| dedup event_id"
=======
    "| eval ticket_id=event_id "
    "| join type=left ticket_id [| inputlookup notable_review_tracking.csv] "
    "| eval open_duration=round(closed_time - created_time, 0) "
    "| eval escalation_status=if(disposition_label=\"True Positive - Escalated\",\"Escalated\",\"Not Escalated\") "
    "| table * QA_comments, QA_reviewer, QA_review_time, Score_Playbook_Analysis, Score_Analitical_Thinking, Score_Reporting, Score_Communication, Score_Adaptability, Score_Mistakes, Score_Metrics, Score_Total "
    "| sort - closed_time "
    "| dedup ticket_id"
>>>>>>> 01b0fb7 (major update 13)
)


def build_notable_query(earliest: str = DEFAULT_EARLIEST, latest: str = DEFAULT_LATEST) -> str:
    """Return a complete Splunk `search` string with time bounds and ES macros.

    The returned string is suitable to pass as the `search` parameter for the
    Splunk export API (jobs/export). It starts with the `search` command and
    includes earliest/latest, followed by the ES macro pipeline.
    """
    earliest = earliest or DEFAULT_EARLIEST
    latest = latest or DEFAULT_LATEST
    return f"search earliest={earliest} latest={latest} {_NOTABLE_PIPELINE}"


