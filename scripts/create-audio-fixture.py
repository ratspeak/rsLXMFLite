#!/usr/bin/env python3
"""Regenerate the signed audio fixture with pinned Python validation references.

Pass local read-only checkouts through --rns and --lxmf. No network stack or
interface is started. All keys and audio bytes are deterministic test data.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--rns', type=Path, required=True)
parser.add_argument('--lxmf', type=Path, required=True)
args = parser.parse_args()
refs = {}
for name, directory, expected in [
    ('Reticulum', args.rns, '7f2b3b9b524c9386316379af1313b43a5e4f7a5d'),
    ('LXMF', args.lxmf, 'c3ff2d6dc2f256daab896dadc044dd5a913ecbb7'),
]:
    head = subprocess.check_output(['git', '-C', str(directory), 'rev-parse', 'HEAD'], text=True).strip()
    if head != expected:
        raise SystemExit(f'{name}: unexpected reference {head}')
    if subprocess.check_output(['git', '-C', str(directory), 'status', '--porcelain'], text=True).strip():
        raise SystemExit(f'{name}: reference has local changes')
    refs[name] = head
    sys.path.insert(0, str(directory.resolve()))

import RNS
import LXMF

source = RNS.Identity.from_bytes(bytes([0x51]) * 64)
recipient = RNS.Identity.from_bytes(bytes([0x52]) * 64)
src = RNS.Destination(source, RNS.Destination.OUT, RNS.Destination.SINGLE, 'lxmf', 'delivery')
dst = RNS.Destination(recipient, RNS.Destination.OUT, RNS.Destination.SINGLE, 'lxmf', 'delivery')
for dest in [src, dst]:
    RNS.Identity.remember(bytes(32), dest.hash, dest.identity.get_public_key())
# Opaque binary tests the audio-field container; it does not represent speech.
audio = bytes(i % 251 for i in range(1500))
message = LXMF.LXMessage(dst, src, 'Voice message', '', {LXMF.FIELD_AUDIO: [LXMF.AM_CODEC2_700C, audio]}, desired_method=LXMF.LXMessage.DIRECT)
message.timestamp = 1234567890.5
message.pack()
parsed = LXMF.LXMessage.unpack_from_bytes(message.packed)
assert parsed.signature_validated
assert parsed.fields[LXMF.FIELD_AUDIO] == [LXMF.AM_CODEC2_700C, audio]
assert parsed.hash == message.hash
folder = Path(__file__).resolve().parents[1] / 'tests' / 'fixtures'
folder.mkdir(exist_ok=True)
(folder / 'audio-700c.lxmf').write_bytes(message.packed)
record = {
    'scope': 'signed LXMF container; opaque synthetic bytes, not speech or network delivery',
    'references': refs,
    'timestamp': message.timestamp,
    'source_test_key': '51 repeated 64 times',
    'recipient_test_key': '52 repeated 64 times',
    'audio_bytes': len(audio),
    'audio_generator': 'byte i is i % 251',
    'audio_mode': LXMF.AM_CODEC2_700C,
    'packed_bytes': len(message.packed),
    'packed_sha256': hashlib.sha256(message.packed).hexdigest(),
    'message_id': message.hash.hex(),
    'python_signature_validated': parsed.signature_validated,
}
(folder / 'audio-700c.json').write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps(record, indent=2))
