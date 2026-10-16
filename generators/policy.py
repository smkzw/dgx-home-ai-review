# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""R13 fixed SOURCE slots. No runtime issue/window/permission."""
import json
from pathlib import Path
HERE = Path(__file__).resolve().parent
CONTRACT = json.loads((HERE.parent / 'SOURCE_CONTRACT.json').read_bytes())
EPOCH = CONTRACT['source_epoch']
BUSINESS = CONTRACT['business_composition_operation']
ASSET_OPERATION = CONTRACT['operation_family']
PC_ROOT = CONTRACT['PC_ROOT']
PC_DATA = PC_ROOT + '-data'
A_ROOT = CONTRACT['A_ROOT']
A_DATA = CONTRACT['A_DATA']
PC_UNIT = 'dgx-v4-mimo-registry-PC-r16.service'
A_ENTRY_UNIT = 'dgx-v4-mimo-registry-native-role-context-r14.service'
FAMILY = 'role-context-r14'
OLD_PC = '/opt/dgx-v4/hx/mimo-registry-native-r26-asset-protocol-r12'
OLD_A = '/opt/dgx-v4/mimo-registry-native-r26-asset-protocol-r12'
OLD_DATA = '/var/lib/dgx-v4/mimo-registry-native-r26-asset-protocol-r12'
OLD_STAGE = 'd8d0f06cc54a807f320d03813daf3b4b'
ACTUAL_ISSUED = ACTUAL_CURRENT = ACTUAL_NONCE = ACTUAL_PERMIT = None
DEPENDENCY_PENDING = ('final affected CPU and physical bytes acceptance', 'parent final independent review and fresh native admission')
ENTRY_PHASE = 'LIVE_IDLE_FAILED_TERMINAL_HELD'
OLD_GRANT_OPERATION = ASSET_OPERATION
