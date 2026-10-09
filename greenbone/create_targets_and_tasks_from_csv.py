import argparse
import csv
import ipaddress
import os
from pathlib import Path

from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeCheckCommandTransform

BASE_DIR = Path(__file__).resolve().parent
SOCKET = '/run/gvmd/gvmd.sock'
#PORT_LIST_ID   = "9fe2476e-6af3-4151-a61b-469d1c57e321"   # All TCP and UDP
#PORT_LIST_ID   = "4a4717fe-57d2-11e1-9a26-406186ea4fc5"   # All IANA assigned TCP and UDP
PORT_LIST_ID   = "730ef368-57e2-11e1-a90f-406186ea4fc5"   # All TCP and Nmap top 100 UDP
SCAN_CONFIG_ID = "daba56c8-73ec-11df-a475-002264764cea"   # Full and fast
SCANNER_ID     = "08b69003-5fc2-4037-a479-93b440211c73"   # OpenVAS Default


def read_networks(path):
    networks = []
    with path.open(encoding='utf-8-sig', newline='') as source:
        reader = csv.DictReader(line for line in source if line.strip() and not line.lstrip().startswith('#'))
        if reader.fieldnames != ['network', 'mask']:
            raise ValueError('CSV must have the header: network,mask')
        for row in reader:
            if None in row or any(value is None for value in row.values()):
                raise ValueError(f'Invalid CSV row: {row}')
            try:
                network = ipaddress.IPv4Network(f"{row['network'].strip()}/{row['mask'].strip()}", strict=True)
            except ValueError as exc:
                raise ValueError(f'Invalid network {row}: {exc}') from exc
            subnet = str(network)
            if subnet not in networks:
                networks.append(subnet)
    return networks


def format_name(subnet):
    address, prefix = subnet.split('/')
    return '.'.join(f'{int(octet):03d}' for octet in address.split('.')) + '/' + prefix


def sync_networks(gmp, networks, dry_run=False):
    targets = gmp.get_targets(filter_string='rows=-1').findall('target')
    tasks = gmp.get_tasks(filter_string='rows=-1').findall('task')
    targets_by_name = {target.findtext('name'): target for target in targets}
    targets_by_hosts = {target.findtext('hosts', '').strip(): target for target in targets}
    task_names = {task.findtext('name') for task in tasks}
    task_targets = {task.find('target').get('id') for task in tasks if task.find('target') is not None}
    counts = dict(targets_created=0, targets_skipped=0, tasks_created=0, tasks_skipped=0)
    for subnet in networks:
        name = format_name(subnet)
        target = targets_by_name.get(name)
        if target is not None and target.findtext('hosts', '').strip() != subnet:
            raise ValueError(f'Target {name} exists with different hosts; refusing to use it')
        if target is None:
            target = targets_by_hosts.get(subnet)
        target_id = target.get('id') if target is not None else None
        if target is not None:
            print(f'[skip] Target {target.findtext("name")}')
            counts['targets_skipped'] += 1
        else:
            print(f'[{"plan" if dry_run else "create"}] Target {name}')
            if not dry_run:
                response = gmp.create_target(name=name, hosts=[subnet], comment=subnet, port_list_id=PORT_LIST_ID)
                target_id = response.get('id')
            counts['targets_created'] += 1

        # Also recognize existing tasks linked to the target under a legacy name.
        if name in task_names or (target_id is not None and target_id in task_targets):
            print(f'[skip] Task for {name}')
            counts['tasks_skipped'] += 1
            continue
        print(f'[{"plan" if dry_run else "create"}] Task {name}')
        if not dry_run:
            gmp.create_task(name=name, config_id=SCAN_CONFIG_ID, target_id=target_id,
                            scanner_id=SCANNER_ID, comment=subnet)
        counts['tasks_created'] += 1
    print(('Dry run: ' if dry_run else 'Completed: ') + ', '.join(f'{key}={value}' for key, value in counts.items()))
    return counts


def main():
    parser = argparse.ArgumentParser(
        description='Create Greenbone targets and tasks from networks_excluded.csv; skip existing entries.'
    )
    parser.add_argument('--csv', type=Path, default=BASE_DIR.parent / 'networks_excluded.csv')
    parser.add_argument('--dry-run', action='store_true', help='Read Greenbone and show planned changes without creating anything')
    args = parser.parse_args()
    networks = read_networks(args.csv)
    try:
        from dotenv import load_dotenv
    except ImportError:
        pass
    else:
        load_dotenv(BASE_DIR / '.env')
    user, password = os.environ.get('GVM_USER'), os.environ.get('GVM_PASS')
    if not user or not password:
        parser.error('Set GVM_USER and GVM_PASS in the environment or in greenbone/.env (requires python-dotenv).')
    with Gmp(UnixSocketConnection(path=SOCKET), transform=EtreeCheckCommandTransform()) as gmp:
        gmp.authenticate(user, password)
        sync_networks(gmp, networks, dry_run=args.dry_run)


if __name__ == '__main__':
    main()
