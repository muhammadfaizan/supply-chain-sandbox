"""Dependency supply-chain screening.

Stages, run in order by cli.main():
  detect    find the ecosystems and manifest files        (detect.py)
  static    known vulnerabilities, heuristics, source     (checks.py, via runner.py)
  dynamic   install a Python package in the sandbox       (dynamic.py)
  report    write the Markdown report and the verdict     (report.py, models.py)
"""
