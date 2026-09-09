from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _resolve_package_version


def _parse_version():
    for pkg in ("pysaml2-fork", "pysaml2"):
        try:
            return _resolve_package_version(pkg)
        except PackageNotFoundError:
            continue
    return ""


version = _parse_version()

