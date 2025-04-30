from lxml import etree
import base64
import re

def parse_svg(file_path):
    try:
        tree = etree.parse(file_path)
        return tree
    except Exception as e:
        print(f"[ERROR] Failed to parse SVG: {e}")
        return None

def check_event_handlers(tree):
    results = []
    for element in tree.iter():
        for attr_name, attr_value in element.attrib.items():
            if attr_name.lower().startswith("on"):
                results.append({
                    "tag": element.tag,
                    "line": element.sourceline,
                    "attribute": attr_name,
                    "code": attr_value.strip()
                })
    return results

def check_external_links(tree):
    results = []
    for element in tree.iter():
        for attr in element.attrib:
            # Extract full attribute name (namespaced or not)
            attr_name = attr
            attr_value = element.attrib[attr]

            # Handle href, src, and xlink:href regardless of namespace
            if (
                ("href" in attr_name or "src" in attr_name)
                and ("http://" in attr_value or "https://" in attr_value)
            ):
                results.append({
                    "tag": element.tag,
                    "line": element.sourceline,
                    "attribute": attr_name,
                    "url": attr_value
                })

    return results

def check_base64(tree):
    results = []
    base64_pattern = re.compile(r'data:[^;]+;base64,([a-zA-Z0-9+/=\n\r]+)')

    for element in tree.iter():
        for attr_name, attr_value in element.attrib.items():
            matches = base64_pattern.findall(attr_value)
            for match in matches:
                try:
                    decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                    preview = decoded.strip()[:50]
                except Exception:
                    preview = "[UNDECODABLE]"

                results.append({
                    "tag": element.tag,
                    "line": element.sourceline,
                    "attribute": attr_name,
                    "preview": preview
                })

    return results

def check_foreign_objects(tree):
    results = []
    for element in tree.iter():
        try:
            tag = etree.QName(element).localname.lower()
        except Exception:
            continue  # skip if it's not a valid tag

        if tag == "foreignobject":
            results.append({
                "tag": element.tag,
                "line": element.sourceline,
                "content": (element.text or "").strip()
            })
    return results

def check_css_imports(tree):
    results = []
    for element in tree.iter():
        try:
            tag = etree.QName(element).localname.lower()
        except Exception:
            continue  # Skip malformed or non-element entries

        if tag == "style":
            css = (element.text or "").strip()
            if "http://" in css or "https://" in css:
                if "@import" in css or "url(" in css:
                    results.append({
                        "tag": element.tag,
                        "line": element.sourceline,
                        "code": css[:80] + ("..." if len(css) > 80 else "")
                    })
    return results

def check_obfuscation(tree):
    results = []
    unicode_pattern = re.compile(r'\\u[0-9a-fA-F]{4}')
    eval_pattern = re.compile(r'eval\s*\(')
    charcode_pattern = re.compile(r'String\.fromCharCode\s*\(')

    for element in tree.iter():
        # Check inner text
        if element.text:
            text = element.text.strip()
            if unicode_pattern.search(text) or eval_pattern.search(text) or charcode_pattern.search(text):
                results.append({
                    "tag": element.tag,
                    "line": element.sourceline,
                    "type": "innerText",
                    "code": text[:80] + ("..." if len(text) > 80 else "")
                })

        # Check attributes
        for attr_name, attr_value in element.attrib.items():
            if unicode_pattern.search(attr_value) or eval_pattern.search(attr_value) or charcode_pattern.search(attr_value):
                results.append({
                    "tag": element.tag,
                    "line": element.sourceline,
                    "type": f"attribute:{attr_name}",
                    "code": attr_value[:80] + ("..." if len(attr_value) > 80 else "")
                })

    return results

def check_entity_expansion_from_raw(file_path):
    results = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            raw_text = f.read()

        if "<!DOCTYPE" in raw_text or "<!ENTITY" in raw_text:
            lines = raw_text.splitlines()
            for i, line in enumerate(lines, start=1):
                if "<!DOCTYPE" in line or "<!ENTITY" in line:
                    results.append({
                        "line": i,
                        "code": line.strip()
                    })
    except Exception as e:
        print(f"[ERROR] Failed to read raw SVG for entity check: {e}")
    
    return results

def calculate_threat_score(results_dict):
    score = 0

    weights = {
        "scripts": 30,
        "events": 20,
        "links": 15,
        "base64": 25,
        "foreign": 25,
        "css": 20,
        "obfuscation": 30,
        "entity": 40
    }

    for key, weight in weights.items():
        score += len(results_dict.get(key, [])) * weight

    if score >= 60:
        level = "HIGH RISK"
    elif score >= 30:
        level = "SUSPICIOUS"
    else:
        level = "PROBABLY SAFE"

    return score, level

if __name__ == "__main__":
    file_path = "test_files/test_master.svg"
    tree = parse_svg(file_path)
    if tree:
        print("[OK] SVG parsed successfully.")

        event_results = check_event_handlers(tree)
        link_results = check_external_links(tree)
        base64_results = check_base64(tree)
        foreign_results = check_foreign_objects(tree)
        css_results = check_css_imports(tree)
        obfuscation_results = check_obfuscation(tree)
        expansion_results = check_entity_expansion_from_raw(file_path)

        results_dict = {
            "scripts": [],
            "events": event_results,
            "links": link_results,
            "base64": base64_results,
            "foreign": foreign_results,
            "css": css_results,
            "obfuscation": obfuscation_results,
            "entity": expansion_results
        }

        score, risk_level = calculate_threat_score(results_dict)

        print("\n=== FINAL REPORT ===")
        print(f"[+] Total Threat Score: {score}")
        print(f"[+] Classification: {risk_level}")