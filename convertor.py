import json

def convert_d3fend(d3fend_full_mappings):
    mapping = {}

    for entry in d3fend_full_mappings["results"]["bindings"]:
        technique_id = entry["off_tech_id"]["value"]
        off_label = entry["off_tech_label"]["value"]

        def_tech = entry.get("def_tech_label", {}).get("value")
        query_def_tech = entry.get("query_def_tech_label", {}).get("value")

        if technique_id not in mapping:
            mapping[technique_id] = {
                "off_tech_label": off_label,
                "countermeasures": set(), 
                "actions": ["alert_only"]  
            }

        if def_tech:
            mapping[technique_id]["countermeasures"].add(def_tech)
        if query_def_tech:
            mapping[technique_id]["countermeasures"].add(query_def_tech)

    for k in mapping:
        mapping[k]["countermeasures"] = list(mapping[k]["countermeasures"])

    return mapping


if __name__ == "__main__":
    with open("d3fend_full_mappings.json", "r") as f:
        raw_data = json.load(f)

    compact_map = convert_d3fend(raw_data)

    with open("compact_d3fend.json", "w") as f:
        json.dump(compact_map, f, indent=2)

    print("Conversion complete! See compact_d3fend.json")