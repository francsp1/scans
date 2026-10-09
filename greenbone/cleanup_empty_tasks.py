import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeCheckCommandTransform

parser = argparse.ArgumentParser()
parser.add_argument('--delete', action='store_true')
args = parser.parse_args()
base = Path(__file__).resolve().parent
load_dotenv(base / '.env')


def task_info(task):
    count = task.findtext('report_count')
    return {
        'id': task.get('id'),
        'name': task.findtext('name'),
        'status': task.findtext('status'),
        'report_count': int(count.strip()) if count and count.strip().isdigit() else None,
    }


with Gmp(UnixSocketConnection(path='/run/gvmd/gvmd.sock'),
         transform=EtreeCheckCommandTransform()) as gmp:
    gmp.authenticate(os.environ['GVM_USER'], os.environ['GVM_PASS'])
    response = gmp.get_tasks(filter_string='rows=-1')
    tasks = [task_info(task) for task in response.findall('task')]
    candidates = [task for task in tasks if task['report_count'] == 0]
    print(json.dumps({'tasks': len(tasks), 'zero_reports': len(candidates),
                      'unknown_counts': sum(t['report_count'] is None for t in tasks),
                      'candidate_statuses': sorted({t['status'] for t in candidates})}, indent=2))
    if args.delete:
        log_path = base / ('task-cleanup-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '.jsonl')
        with log_path.open('x') as log:
            for candidate in candidates:
                current = gmp.get_task(candidate['id']).find('task')
                info = task_info(current)
                if info['report_count'] != 0:
                    continue
                result = gmp.delete_task(candidate['id'], ultimate=False)
                log.write(json.dumps({**info, 'response_status': result.get('status'),
                                      'response_text': result.get('status_text'),
                                      'utc': datetime.now(timezone.utc).isoformat()}) + '\n')
                log.flush()
        remaining = [task_info(t) for t in gmp.get_tasks(filter_string='rows=-1').findall('task')]
        protected = {t['id'] for t in tasks if t['report_count'] != 0}
        assert protected.issubset({t['id'] for t in remaining}), 'A protected task is missing'
        print(json.dumps({'audit': str(log_path), 'remaining': len(remaining),
                          'remaining_zero_reports': [t for t in remaining if t['report_count'] == 0]}, indent=2))
