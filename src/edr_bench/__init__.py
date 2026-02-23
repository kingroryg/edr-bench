"""EDR-Bench: Sandboxed benchmarking suite for evaluating AI-enhanced EDR tools."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("edr-bench")
except PackageNotFoundError:
    __version__ = "0.1.0"
