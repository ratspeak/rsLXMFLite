#!/usr/bin/env python3
"""Regenerate the results/ticket fixture with pinned Python validation references.

Pass local read-only checkouts through --rns and --lxmf. No network stack or
interface is started. Keys, tickets and results are deterministic test data;
ECIES ephemerals and proof-of-work stamps come from the reference and are recorded.
Every message is packed, parsed, signature-checked and stamp-checked by the
references themselves.
"""
import argparse
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
import RNS.vendor.umsgpack as msgpack
import LXMF

TIMESTAMP = 1234567890.5
STAMP_COST = 8
node = RNS.Identity.from_bytes(bytes([0x51]) * 64)
manager = RNS.Identity.from_bytes(bytes([0x52]) * 64)
node_dest = RNS.Destination(node, RNS.Destination.OUT, RNS.Destination.SINGLE, 'lxmf', 'delivery')
manager_dest = RNS.Destination(manager, RNS.Destination.OUT, RNS.Destination.SINGLE, 'lxmf', 'delivery')
for dest in [node_dest, manager_dest]:
    RNS.Identity.remember(bytes(32), dest.hash, dest.identity.get_public_key())
ratchet_private = bytes([0x53]) * 32
ticket = bytes(range(0xa0, 0xb0))
ticket_expires = TIMESTAMP + LXMF.LXMessage.TICKET_EXPIRY

# Integer-keyed results map, as a node /status reply carries it.
results = {
    0x00: 1,
    0x01: 'status',
    0x02: '1.0.0',
    0x03: True,
    0x04: 86400,
    0x05: 1,
    0x06: [869525000, 250000, 11, 5, 22],
    0x07: 0,
    0x08: 1800,
    0x09: 2,
    0x0A: 3,
    0x0D: bytes([0x80, 0x81, 0x01]),
}
results_encoded = msgpack.packb(results)
extension_encoded = msgpack.packb('ext')


def build(source, destination, content, fields, method, outbound_ticket=None, stamp_cost=None):
    message = LXMF.LXMessage(destination, source, content, '', fields, desired_method=method, stamp_cost=stamp_cost)
    message.timestamp = TIMESTAMP
    message.defer_stamp = False
    message.outbound_ticket = outbound_ticket
    message.pack()
    assert message.method == method
    parsed = LXMF.LXMessage.unpack_from_bytes(message.packed)
    assert parsed.signature_validated
    assert parsed.hash == message.hash
    assert parsed.fields == fields
    return message, parsed


vectors = []


def record(name, message, parsed, recipient, ratchet=False, **extra):
    entry = {
        'name': name,
        'method': 'opportunistic' if message.method == LXMF.LXMessage.OPPORTUNISTIC else 'direct',
        'content': message.content.decode(),
        'fields': sorted(parsed.fields),
        'packed': message.packed.hex(),
        'message_id': message.hash.hex(),
        'stamp': parsed.stamp.hex() if parsed.stamp else None,
        'python_signature_validated': parsed.signature_validated,
    }
    if message.method == LXMF.LXMessage.OPPORTUNISTIC:
        plaintext = message.packed[LXMF.LXMessage.DESTINATION_LENGTH:]
        if ratchet:
            encrypted = recipient.encrypt(plaintext, ratchet=RNS.Identity._ratchet_public_bytes(ratchet_private))
            assert recipient.decrypt(encrypted) is None
            assert recipient.decrypt(encrypted, ratchets=[ratchet_private]) == plaintext
        else:
            encrypted = recipient.encrypt(plaintext)
            assert recipient.decrypt(encrypted) == plaintext
        entry['encrypted'] = encrypted.hex()
        entry['ratchet'] = ratchet
    entry.update(extra)
    vectors.append(entry)


reply = 'Status: forwarding on, up 1 day.'
fields = {LXMF.FIELD_RESULTS: results}

message, parsed = build(node_dest, manager_dest, reply, fields, LXMF.LXMessage.DIRECT)
assert parsed.fields[LXMF.FIELD_RESULTS][0x00] == 1
record('direct_results', message, parsed, manager)

two = {LXMF.FIELD_RESULTS: results, 0xFD: 'ext'}
message, parsed = build(node_dest, manager_dest, reply, two, LXMF.LXMessage.DIRECT)
record('direct_results_and_extension', message, parsed, manager)

message, parsed = build(node_dest, manager_dest, reply, fields, LXMF.LXMessage.DIRECT, outbound_ticket=ticket)
assert parsed.validate_stamp(STAMP_COST, tickets=[ticket]) and parsed.stamp_value == LXMF.LXMessage.COST_TICKET
assert not parsed.validate_stamp(STAMP_COST)
record('direct_results_ticket', message, parsed, manager, python_stamp_validated=True)

message, parsed = build(node_dest, manager_dest, reply, fields, LXMF.LXMessage.DIRECT, stamp_cost=STAMP_COST)
assert parsed.validate_stamp(STAMP_COST)
record('direct_results_pow', message, parsed, manager, python_stamp_validated=True, stamp_cost=STAMP_COST)

message, parsed = build(node_dest, manager_dest, reply, fields, LXMF.LXMessage.OPPORTUNISTIC)
record('opportunistic_results', message, parsed, manager)

message, parsed = build(node_dest, manager_dest, reply, fields, LXMF.LXMessage.OPPORTUNISTIC)
record('opportunistic_results_ratchet', message, parsed, manager, ratchet=True)

message, parsed = build(node_dest, manager_dest, reply, fields, LXMF.LXMessage.OPPORTUNISTIC, outbound_ticket=ticket)
assert parsed.validate_stamp(STAMP_COST, tickets=[ticket])
record('opportunistic_results_ticket', message, parsed, manager, python_stamp_validated=True)

message, parsed = build(node_dest, manager_dest, reply, fields, LXMF.LXMessage.OPPORTUNISTIC, stamp_cost=STAMP_COST)
assert parsed.validate_stamp(STAMP_COST)
record('opportunistic_results_ratchet_pow', message, parsed, manager, ratchet=True,
       python_stamp_validated=True, stamp_cost=STAMP_COST)

# Manager command carrying the router's native ticket shape (LXMRouter.generate_ticket).
command = {LXMF.FIELD_TICKET: [ticket_expires, ticket]}
message, parsed = build(manager_dest, node_dest, '/status', command, LXMF.LXMessage.OPPORTUNISTIC)
record('inbound_command_ticket', message, parsed, node)

folder = Path(__file__).resolve().parents[1] / 'tests' / 'fixtures'
folder.mkdir(exist_ok=True)
document = {
    'scope': 'signed LXMF results replies with ticket and proof-of-work stamps; no network delivery',
    'references': refs,
    'timestamp': TIMESTAMP,
    'node_test_key': '51 repeated 64 times',
    'manager_test_key': '52 repeated 64 times',
    'ratchet_private': ratchet_private.hex(),
    'ticket': ticket.hex(),
    'ticket_expires': ticket_expires,
    'results_encoded': results_encoded.hex(),
    'extension_field': 0xFD,
    'extension_encoded': extension_encoded.hex(),
    'vectors': vectors,
}
(folder / 'field-results.json').write_text(json.dumps(document, indent=2) + '\n')
print(f'{len(vectors)} vectors written')
