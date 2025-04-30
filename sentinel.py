import argparse
from scanner import (
    parse_svg,
    check_event_handlers,
    check_external_links,
    check_base64,
    check_foreign_objects,
    check_css_imports,
    check_obfuscation,
    check_entity_expansion_from_raw,
    calculate_threat_score
)

def run_svg_scan(file_path):
    tree = parse_svg(file_path)
    results_dict = {}

    if tree:
        print(f"[OK] Parsed: {file_path}")

        results_dict["events"] = check_event_handlers(tree)
        results_dict["links"] = check_external_links(tree)
        results_dict["base64"] = check_base64(tree)
        results_dict["foreign"] = check_foreign_objects(tree)
        results_dict["css"] = check_css_imports(tree)
        results_dict["obfuscation"] = check_obfuscation(tree)
        results_dict["entity"] = check_entity_expansion_from_raw(file_path)
        results_dict["scripts"] = []  # Reserved for future

        score, level = calculate_threat_score(results_dict)

        print("\n=== SUMMARY REPORT ===")
        print(f"[+] Threat Score: {score}")
        print(f"[+] Classification: {level}\n")

        for key, results in results_dict.items():
            if results:
                print(f"[ALERT] {key.upper()} → {len(results)} detection(s)")
            else:
                print(f"[CLEAN] {key.upper()} → No issues")

    else:
        print("[ERROR] Could not parse the SVG.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run SVG Sentinel scan")
    parser.add_argument("--file", required=True, help="Path to SVG file to scan")
    args = parser.parse_args()

    run_svg_scan(args.file)