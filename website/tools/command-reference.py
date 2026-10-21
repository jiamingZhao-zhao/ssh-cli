"""Generate/check command metadata from a v0.7.31 binary's help output only.

python website/tools/command-reference.py --cli /path/to/ssh-cli [--check]
Every inventory request ends in --help and uses an isolated config directory.
No command action, SSH connection, credential read or network request is made.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--cli', type=Path, required=True)
parser.add_argument('--check', action='store_true')
args = parser.parse_args()
binary = args.cli.resolve(strict=True)
version = subprocess.check_output([str(binary), 'version'], text=True).strip()
if version.split()[:2] != ['ssh-cli', '0.7.31']:
    raise SystemExit('Use a binary built from v0.7.31.')

headings = {'Usage:', 'Aliases:', 'Examples:', 'Available Commands:', 'Flags:', 'Global Flags:', 'Additional help topics:'}


def sections(help_text):
    result = {'description': []}
    section = 'description'
    for line in help_text.splitlines():
        if line.strip() in headings:
            section = line.strip()[:-1]
            result[section] = []
        else:
            result[section].append(line)
    return {name: '\n'.join(lines).strip() for name, lines in result.items()}


def flags(block):
    result = []
    for line in block.splitlines():
        stripped = line.strip()
        if stripped.startswith('Use "ssh-cli '):
            break
        if not stripped:
            continue
        if not stripped.startswith('-'):
            if result:
                result[-1]['description'] += ' ' + stripped
            continue
        parts = re.split(r'\s{2,}', stripped, maxsplit=1)
        if len(parts) != 2:
            raise ValueError('Unparsed flag: ' + line)
        specification, description = parts
        match = re.fullmatch(r'(?:-(\w), )?--([\w-]+)(?: (\S+))?', specification)
        if not match:
            raise ValueError('Unparsed flag specification: ' + specification)
        short, name, value_type = match.groups()
        result.append({'name': name, 'short': short or '', 'type': value_type or 'bool', 'description': description})
    return result


commands = []
summaries = {}
with tempfile.TemporaryDirectory(prefix='ssh-cli-command-docs-') as temporary:
    pending = [()]
    seen = set()
    while pending:
        path = pending.pop(0)
        if path in seen:
            continue
        seen.add(path)
        if len(seen) > 200:
            raise RuntimeError('Unexpected command tree size.')
        help_text = subprocess.check_output(
            [str(binary), '--config', temporary, *path, '--help'], text=True, encoding='utf-8'
        ).replace('\r\n', '\n')
        content = sections(help_text)
        if 'Usage' not in content:
            raise ValueError('Missing usage: ' + ' '.join(path))
        children = []
        for line in content.get('Available Commands', '').splitlines():
            match = re.match(r'^\s*([a-z0-9][a-z0-9_-]*)\s{2,}(.+?)\s*$', line)
            if not match:
                raise ValueError('Unparsed subcommand: ' + line)
            child = match.group(1)
            children.append('-'.join((*path, child)))
            summaries[(*path, child)] = match.group(2)
            pending.append((*path, child))
        # Cobra deliberately hides shell completion in the root help. It is
        # still a supported user command; __complete is an internal protocol.
        if not path:
            pending.append(('completion',))
            children.append('completion')
        description = content['description']
        commands.append({
            'id': '-'.join(path) or 'root', 'path': ' '.join(('ssh-cli', *path)),
            'summary': summaries.get(path, ' '.join(description.split('\n\n', 1)[0].splitlines())), 'description': description,
            'usage': content['Usage'].split('\n\nUse "ssh-cli', 1)[0],
            'aliases': content.get('Aliases', ''), 'examples': content.get('Examples', ''),
            'children': children, 'flags': flags(content.get('Flags', '')),
            'globalFlags': flags(content.get('Global Flags', '')),
            'help': help_text.strip(),
        })

directory = Path(__file__).resolve().parents[1]
notes = json.loads((directory / 'command-notes.json').read_text(encoding='utf-8'))['entries']
ids = {command['id'] for command in commands}
if ids != set(notes):
    raise SystemExit(f'Notes must cover every command. Missing: {ids - set(notes)}; extra: {set(notes) - ids}')
for command in commands:
    root = command['path'].split()[1:2]
    root = root[0] if root else 'root'
    command['category'] = (
        'execution' if root in ('exec', 'ui', 'session', 'daemon') else
        'files' if root in ('upload', 'download', 'ls', 'relay') else
        'inventory' if root in ('host', 'group', 'env') else
        'policy' if root in ('policy', 'elevate') else
        'records' if root in ('audit', 'history') else
        'configuration' if root in ('config', 'import', 'keys') else 'tools'
    )
    command['note'] = notes[command['id']]
    command['searchFlags'] = ' '.join(
        '--' + flag['name'] + (' -' + flag['short'] if flag['short'] else '')
        for flag in command['flags'] + command['globalFlags']
    )
data = {'version': '0.7.31', 'commit': '5e52d45c277783352d699d7abf2779275a0f2f47', 'commands': commands}
index = {'version': data['version'], 'commands': [
    {key: command[key] for key in ('id', 'path', 'summary', 'category', 'searchFlags')} |
    {'title': command['note']['title'], 'effect': command['note']['effect']}
    for command in commands
]}
for filename, name, value in [('command-data.js', 'SSH_CLI_COMMAND_REFERENCE', data),
                               ('command-index.js', 'SSH_CLI_COMMAND_INDEX', index)]:
    payload = ('// Generated by tools/command-reference.py from CLI help and reviewed notes.\n'
               'window.' + name + ' = ' + json.dumps(value, ensure_ascii=False, separators=(',', ':')) + ';\n')
    destination = directory / filename
    if args.check:
        if destination.read_text(encoding='utf-8') != payload:
            raise SystemExit(f'{filename} differs from CLI help/notes. Regenerate and review the diff.')
    else:
        destination.write_text(payload, encoding='utf-8', newline='\n')
print(f'{"Checked" if args.check else "Generated"} {len(commands)} entries against {version}; help only, no SSH.')
