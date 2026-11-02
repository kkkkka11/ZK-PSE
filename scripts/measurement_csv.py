"""Shared CSV record parsing and exports for measurement summaries."""
import csv


def metric_blocks(path, marker):
    blocks, block = [], {}
    with path.open(newline="") as source:
        for key, value in csv.reader(source):
            if key == "metric":
                continue
            if key == marker and block:
                blocks.append(block)
                block = {}
            if key in block:
                raise ValueError(f"Duplicate field within a record: {path}: {key}")
            block[key] = value
    if block:
        blocks.append(block)
    if not blocks or any(set(b) != set(blocks[-1]) for b in blocks):
        raise ValueError(f"Incomplete measurement blocks: {path}")
    return blocks



def save(path, rows):
    if rows:
        with path.open("w", newline="") as target:
            writer = csv.DictWriter(target, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
