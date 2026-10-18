"""Exact vector bytes from Python (including signed zero and subnormals)."""
import json
from pathlib import Path
from tds import types
from tds.wire import Writer
cases=[]
for element,numbers in [(types.VectorElement.FLOAT32,(1.,2.5,-3.4028234663852886e38,2.**-149,-0.)),(types.VectorElement.FLOAT16,(1.,2.5,-65504.,2.**-24,-0.))]:
    t=types.vector(len(numbers),element)
    for v in [types.SqlVector(element,numbers),None]:
        w=Writer(record=False);t.write_info(w);t.write_value(w,v)
        cases.append(dict(name=str(t),wire=bytes(w.buf).hex()))
Path(__file__).with_name('python.json').write_text(json.dumps(cases,indent=2)+'\n')
print(len(cases),'Python vector cases')
