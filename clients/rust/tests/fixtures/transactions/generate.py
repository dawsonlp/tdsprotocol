"""Actual Python transaction-manager codec, synthetic inputs only."""
import json
from pathlib import Path
from tds import transactions as t
from tds.requests import Context
cases = []
requests = [t.CoordinatorAddress(), t.Propagate(b'cookie'), t.Promote(), t.Begin(),
            t.Begin(t.Isolation.SERIALIZABLE, 'a🦀'), t.Save('before'), t.Save(''),
            t.Commit(), t.Rollback('before'), t.Commit('outer', t.Begin(t.Isolation.SNAPSHOT, 'next')),
            t.Rollback(begin=t.Begin()), t.Begin(name='\ud800')]
for descriptor, outstanding in [(0, 4), (123, 2)]:
    for request in requests:
        encoded = request.encode(Context(descriptor, outstanding, b''), False)
        cases.append(dict(name=repr(request), transaction=descriptor, outstanding=outstanding, body=encoded.body.hex()))
Path(__file__).with_name('python.json').write_text(json.dumps(cases, indent=2) + '\n')
print(len(cases), 'Python transaction cases')
