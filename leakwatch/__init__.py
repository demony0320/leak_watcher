"""LeakWatch — leak detection in two stages.

  ci/       repository scan for CI (Bitbucket Pipelines / Code Insights)
  runtime/  scheduled checks against running systems (http, nuclei, db) + CI ingest
  common/   findings, patterns, lifecycle store, alerts, report, LLM triage

Core runs on the Python standard library only (3.11+). Optional: SQLAlchemy + driver.
"""

__version__ = "0.2.0"
