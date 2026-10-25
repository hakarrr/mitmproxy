import io
import json
from pathlib import Path

import pytest

from mitmproxy import exceptions
from mitmproxy import flowfilter
from mitmproxy.addons.savehar import SaveHar
from mitmproxy.io import FlowReader
from mitmproxy.io.har import fix_headers
from mitmproxy.io.har import request_to_flow
from mitmproxy.test import tflow
from mitmproxy.tools.web.app import flow_to_json

data_dir = Path(__file__).parent.parent / "data"


def hardcode_variable_fields_for_tests(flow: dict) -> None:
    flow["id"] = "hardcoded_for_test"
    flow["timestamp_created"] = 0
    flow["server_conn"]["id"] = "hardcoded_for_test"
    flow["client_conn"]["id"] = "hardcoded_for_test"


def file_to_flows(path_name: Path) -> list[dict]:
    file_json = json.loads(path_name.read_bytes())["log"]["entries"]
    flows = []

    for entry in file_json:
        expected = request_to_flow(entry)
        flow_json = flow_to_json(expected)
        hardcode_variable_fields_for_tests(flow_json)
        flows.append(flow_json)

    return flows


def test_corrupt():
    file_json = json.loads(
        Path(data_dir / "corrupted_har/broken_headers.json").read_bytes()
    )
    with pytest.raises(exceptions.OptionsError):
        fix_headers(file_json["headers"])


@pytest.mark.parametrize(
    "har_file", [pytest.param(x, id=x.stem) for x in data_dir.glob("har_files/*.har")]
)
def test_har_to_flow(har_file: Path):
    expected_file = har_file.with_suffix(".json")

    expected_flows = json.loads(expected_file.read_bytes())
    actual_flows = file_to_flows(har_file)

    for expected, actual in zip(expected_flows, actual_flows):
        actual = json.loads(json.dumps(actual))

        assert actual == expected


@pytest.mark.parametrize(
    "scheme, port",
    [("http", 8080), ("https", 8443), ("http", 80), ("https", 443)],
)
@pytest.mark.parametrize("server_ip", ["192.0.2.1", "2001:db8::1", None])
def test_server_address_port(scheme: str, port: int, server_ip: str | None):
    flow = tflow.tflow(resp=True)
    flow.request.scheme = scheme
    flow.request.host = "example.com"
    flow.request.port = port
    flow.server_conn.peername = (server_ip, port) if server_ip else None
    har = json.dumps(SaveHar().make_har([flow])).encode()

    imported = next(FlowReader(io.BytesIO(har)).stream())

    assert imported.request.port == port
    assert imported.server_conn.address == ((server_ip, port) if server_ip else None)
    if server_ip:
        assert flowfilter.match(f"~dst :{port}$", imported)
        if port not in (80, 443):
            default_port = 80 if scheme == "http" else 443
            assert not flowfilter.match(f"~dst :{default_port}$", imported)


if __name__ == "__main__":
    for path_name in data_dir.glob("har_files/*.har"):
        print(path_name)

        flows = file_to_flows(path_name)

        with open(data_dir / f"har_files/{path_name.stem}.json", "w") as f:
            json.dump(flows, f, indent=4)
