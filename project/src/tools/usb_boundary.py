"""Output containment guard. Physical USB verification is done by the PS launcher."""
from pathlib import Path
import os
import shutil

def destination(root, path):
    root, path = Path(root), Path(path)
    if not path.is_absolute() or '..' in path.parts or '..' in root.parts:
        raise ValueError('Absolute paths without traversal required')
    resolved_root = root.resolve(strict=True)
    for item in (root, *root.parents, path, *path.parents):
        if item.is_symlink() or (hasattr(item, 'is_junction') and item.is_junction()):
            raise ValueError('Reparse point forbidden')
    resolved = path.resolve(strict=False)
    if resolved == resolved_root or not resolved.is_relative_to(resolved_root):
        raise ValueError('Output outside project root')
    relative = resolved.relative_to(resolved_root)
    if any(':' in part or part.endswith((' ', '.')) for part in relative.parts):
        raise ValueError('Alternate streams and ambiguous names forbidden')
    return resolved

def require_space(root, amount):
    if shutil.disk_usage(root).free < amount + 5 * 1024**3:
        raise OSError('Insufficient space including 5 GiB reserve')
