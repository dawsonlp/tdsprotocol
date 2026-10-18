"""sql_variant bytes from the existing Python scalar corpus and codec."""
import json
from pathlib import Path
from tds import types
from tds.wire import Writer
from test_types import EXACT, LATIN1
cases = []
for t, values in EXACT:
    for value in values:
        if value is None: continue
        w=Writer(record=False); w.context['collation']=LATIN1
        types.sql_variant.write_value(w,types.SqlVariant(t,value))
        base=Writer(record=False);base.context['collation']=LATIN1;t.write_info(base)
        cases.append(dict(name=str(t),info=bytes(base.buf).hex(),payload=bytes(w.buf).hex()))
w=Writer(record=False);types.sql_variant.write_value(w,None)
cases.append(dict(name='NULL',info='',payload=bytes(w.buf).hex()))
Path(__file__).with_name('python.json').write_text(json.dumps(cases,indent=2)+'\n')
print(len(cases),'Python variant cases')
