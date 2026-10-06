import re
import sys
from pathlib import Path
from typing import Any

from omnidim_ui.config import BASE_DIR
from omnidim_ui.endpoints import ENDPOINTS

HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head"}


def parse_openapi_spec(openapi_path: Path) -> dict[str, list[str]]:
    """Parse paths and HTTP methods from OpenAPI 3.x YAML without external dependencies."""
    if not openapi_path.exists():
        raise FileNotFoundError(f"OpenAPI spec file not found: {openapi_path}")

    paths: dict[str, list[str]] = {}
    current_path: str | None = None
    in_paths = False

    with open(openapi_path, encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.rstrip()

            # Detect paths: section root
            if line == "paths:":
                in_paths = True
                continue

            if not in_paths:
                continue

            # Detect end of paths section (another top-level root key like components: or tags:)
            if line and not line.startswith(" ") and not line.startswith("\t"):
                in_paths = False
                break

            # Path lines are indented by 2 spaces: "  /some/path:"
            path_match = re.match(r"^ {2}(/[^:\s]+):", line)
            if path_match:
                current_path = path_match.group(1)
                if current_path not in paths:
                    paths[current_path] = []
                continue

            # HTTP operation lines are indented by 4 spaces: "    get:" / "    post:"
            if current_path:
                method_match = re.match(r"^ {4}([a-z]+):", line)
                if method_match:
                    method = method_match.group(1).lower()
                    if method in HTTP_METHODS and method not in paths[current_path]:
                        paths[current_path].append(method)

    return paths


def check_catalog_drift(spec_path: Path | None = None) -> dict[str, Any]:
    """Compare OpenAPI specification with registered UI endpoints."""
    path = spec_path or (BASE_DIR / "omnidim-openapi.yaml")
    spec_paths = parse_openapi_spec(path)

    spec_operations = set()
    for p, methods in spec_paths.items():
        for m in methods:
            spec_operations.add((m.upper(), p))

    catalog_operations = {(ep["method"].upper(), ep["path"]) for ep in ENDPOINTS}

    unimplemented_in_catalog = spec_operations - catalog_operations
    unlisted_in_openapi = catalog_operations - spec_operations

    total_spec = len(spec_operations)
    total_catalog = len(catalog_operations)
    covered = len(spec_operations & catalog_operations)
    coverage_pct = (covered / total_spec * 100) if total_spec > 0 else 100.0

    return {
        "totalSpecOperations": total_spec,
        "totalCatalogOperations": total_catalog,
        "coveredOperations": covered,
        "coveragePercentage": round(coverage_pct, 2),
        "unimplementedInCatalog": sorted(unimplemented_in_catalog),
        "unlistedInOpenAPI": sorted(unlisted_in_openapi),
    }


def format_drift_report(report: dict[str, Any]) -> str:
    lines = [
        "=" * 60,
        "OmniDimension OpenAPI Drift Report",
        "=" * 60,
        f"Total Spec Operations:    {report['totalSpecOperations']}",
        f"Registered in Control UI: {report['totalCatalogOperations']}",
        f"Matched Operations:       {report['coveredOperations']}",
        f"Coverage:                 {report['coveragePercentage']}%",
    ]
    if report["unlistedInOpenAPI"]:
        lines.append(f"\n[!] {len(report['unlistedInOpenAPI'])} UI endpoints not present in OpenAPI spec:")
        for m, p in report["unlistedInOpenAPI"]:
            lines.append(f"  - {m} {p}")

    if report["unimplementedInCatalog"]:
        lines.append(f"\n[*] {len(report['unimplementedInCatalog'])} OpenAPI spec endpoints unmapped in UI:")
        for m, p in report["unimplementedInCatalog"][:20]:
            lines.append(f"  - {m} {p}")
        if len(report["unimplementedInCatalog"]) > 20:
            lines.append(f"  ... and {len(report['unimplementedInCatalog']) - 20} more.")

    lines.append("=" * 60)
    return "\n".join(lines)


def main() -> None:
    report = check_catalog_drift()
    print(format_drift_report(report))
    if report["unlistedInOpenAPI"]:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
