import os
from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeCheckCommandTransform

try:
    from dotenv import load_dotenv
except ImportError:
    # The Greenbone gvm-tools image does not include python-dotenv. In that
    # environment, GVM_USER and GVM_PASS are supplied by Docker instead.
    pass
else:
    load_dotenv()

SOCKET         = "/run/gvmd/gvmd.sock"
USER           = os.environ["GVM_USER"]
PASS           = os.environ["GVM_PASS"]
#PORT_LIST_ID   = "9fe2476e-6af3-4151-a61b-469d1c57e321"   # All TCP and UDP
#PORT_LIST_ID   = "4a4717fe-57d2-11e1-9a26-406186ea4fc5"   # All IANA assigned TCP and UDP
PORT_LIST_ID   = "730ef368-57e2-11e1-a90f-406186ea4fc5"   # All TCP and Nmap top 100 UDP
SCAN_CONFIG_ID = "daba56c8-73ec-11df-a475-002264764cea"   # Full and fast
SCANNER_ID     = "08b69003-5fc2-4037-a479-93b440211c73"   # OpenVAS Default

SUBNETS = [f"172.16.{octet}.0/24" for octet in range(256)]


def format_name(subnet):
    address, prefix = subnet.split("/")
    padded_address = ".".join(f"{int(octet):03d}" for octet in address.split("."))
    return f"{padded_address}/{prefix}"

connection = UnixSocketConnection(path=SOCKET)
with Gmp(connection, transform=EtreeCheckCommandTransform()) as gmp:
    gmp.authenticate(USER, PASS)

    # --- Step 1: create targets (skip existing) ---
    print("=== Creating targets ===")
    targets_response = gmp.get_targets(filter_string="rows=-1")
    existing_targets = {
        target.findtext("name"): target
        for target in targets_response.findall("target")
    }

    for subnet in SUBNETS:
        target_name = format_name(subnet)
        if target_name in existing_targets:
            target = existing_targets[target_name]
            if target.findtext("comment") != subnet:
                gmp.modify_target(target.get("id"), comment=subnet)
                print(f"[~] {target_name}  =>  comment updated to {subnet}")
            else:
                print(f"[~] {target_name}  =>  already exists, skipping")
            continue
        resp = gmp.create_target(
            name=target_name,
            hosts=[subnet],
            comment=subnet,
            port_list_id=PORT_LIST_ID,
        )
        print(f"[+] {target_name}  =>  {resp.get('id')}")

    # --- Step 2: create tasks for the configured targets (skip existing) ---
    print("\n=== Creating tasks ===")
    tasks_response = gmp.get_tasks(filter_string="rows=-1")
    existing_tasks = {
        task.findtext("name"): task
        for task in tasks_response.findall("task")
    }
    configured_subnets = {format_name(subnet): subnet for subnet in SUBNETS}

    targets_response = gmp.get_targets(filter_string="rows=-1")
    for target in targets_response.findall("target"):
        target_id   = target.get("id")
        target_name = target.findtext("name")
        if target_name not in configured_subnets:
            continue
        task_name = target_name
        subnet = configured_subnets[target_name]

        if task_name in existing_tasks:
            task = existing_tasks[task_name]
            if task.findtext("comment") != subnet:
                gmp.modify_task(task.get("id"), comment=subnet)
                print(f"[~] {task_name}  =>  comment updated to {subnet}")
            else:
                print(f"[~] {task_name}  =>  already exists, skipping")
            continue

        resp = gmp.create_task(
            name=task_name,
            config_id=SCAN_CONFIG_ID,
            target_id=target_id,
            scanner_id=SCANNER_ID,
            comment=subnet,
        )
        print(f"[+] {task_name}  =>  {resp.get('id')}")
