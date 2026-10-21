"""Generate/check the landing page's real CLI explanations, without SSH.

Usage: python website/tools/policy-examples.py --cli /path/to/ssh-cli [--check]
Use a binary built from v0.7.31. All configuration mutations use temporary
directories; the only command inspected is passed to policy explain, never exec.
"""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--cli', required=True, type=Path)
parser.add_argument('--check', action='store_true')
options = parser.parse_args()
binary = options.cli.resolve(strict=True)
version = subprocess.check_output([str(binary), 'version'], text=True)
if version.split()[:2] != ['ssh-cli', '0.7.31']:
    raise SystemExit('Use an ssh-cli binary built from v0.7.31.')

commands = {'disk': 'df -h /', 'restart': 'systemctl restart nginx', 'format': 'mkfs.ext4 /dev/demo-disk'}
records = {}
with tempfile.TemporaryDirectory(prefix='ssh-cli-website-policy-') as temporary:
    for scope in ['off', 'prod', 'both']:
        config = Path(temporary) / scope

        def run(args, expected=(0,)):
            result = subprocess.run([str(binary), '--config', str(config), *args], capture_output=True)
            if result.returncode not in expected:
                raise RuntimeError((args, result.returncode, result.stdout, result.stderr))
            return result

        run(['policy', 'add', 'website-demo', '--mode', 'standard', '--confirm', 'systemctl restart'])
        for environment in ['test', 'prod']:
            run(['group', 'add', 'app-' + environment, '--env', environment, '--policy', 'website-demo'])
            run(['host', 'add', 'demo-' + environment, '--group', 'app-' + environment,
                 '--host', '192.0.2.' + ('10' if environment == 'test' else '20'), '--user', 'deploy', '--agent'])
        if scope != 'off':
            arguments = ['policy', 'dangerous', 'set', '--enable', '--rule', 'mkfs']
            if scope == 'both':
                arguments += ['--env', 'prod', '--env', 'test']
            run(arguments)
        for environment in ['test', 'prod']:
            for kind, command in commands.items():
                result = run(['policy', 'explain', '-H', 'demo-' + environment, '--json', '--', command], (0, 253))
                actual = json.loads(result.stdout)['explanations'][0]
                excerpt = {key: actual[key] for key in ['host', 'env', 'command', 'allowed', 'needsConfirm', 'mode']}
                excerpt['findings'] = actual.get('findings', [])
                excerpt['dangerousCommands'] = {key: actual['dangerousCommands'][key]
                                               for key in ['enabled', 'scope', 'enforcedHere', 'active']}
                records[f'{environment}/{scope}/{kind}'] = {'exitCode': result.returncode, 'explanation': excerpt}

data = {'version': '0.7.31', 'commit': '5e52d45c277783352d699d7abf2779275a0f2f47', 'commands': commands, 'records': records}
payload = ('// Generated from v0.7.31 policy explain in isolated, local-only configurations.\n'
           '// Each explanation is an excerpt; no command was executed on a server.\n'
           'window.SSH_CLI_POLICY_EXAMPLES = ' + json.dumps(data, ensure_ascii=False, separators=(',', ':')) + ';\n')
destination = Path(__file__).resolve().parents[1] / 'policy-examples.js'
if options.check:
    if destination.read_text(encoding='utf-8') != payload:
        raise SystemExit('Policy examples differ from the actual CLI output. Review and regenerate them.')
    print(f'Checked {len(records)} policy explanations against {version.strip()}; no SSH connections.')
else:
    destination.write_text(payload, encoding='utf-8', newline='\n')
    print(f'Generated {len(records)} policy explanations: {destination}')
