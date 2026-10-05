import asyncio
import contextlib
import io
import json
from pathlib import Path
import sys
import unittest

repo = Path(sys.argv[1])
sys.path.insert(0, str(repo/'tests'))
from test_home_bridge import HomeBridgeUDPTests
from fan_ssh.remote import Node
original_result = Node.session_result
def reported(self, task):
    if not task.cancelled() and task.exception():
        print('BACKGROUND SERVICE FAILURE:', type(task.exception()).__name__, str(task.exception()), file=sys.__stderr__, flush=True)
    return original_result(self, task)
Node.session_result = reported

original = HomeBridgeUDPTests.roundtrip
async def observed(self, udp_incoming):
    try:
        await original(self, udp_incoming)
    except BaseException:
        print('BRIDGE FAILURE LOG:', self.log.getvalue(), file=sys.__stderr__, flush=True)
        raise
HomeBridgeUDPTests.roundtrip = observed
result_rows = []
for i in range(6):
    print('REPRO ITERATION', i+1, flush=True)
    suite = unittest.TestSuite([HomeBridgeUDPTests('test_tcp_incoming_udp_outgoing_binary_and_half_close')])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    result_rows.append(dict(iteration=i+1,total=result.testsRun,errors=len(result.errors),failures=len(result.failures)))
print(json.dumps(result_rows), flush=True)
sys.exit(int(any(x['errors'] or x['failures'] for x in result_rows)))
