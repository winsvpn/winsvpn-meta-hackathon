# Resource profile version 1

`winn3-gateway -mode resources -max-sessions 64 -path-mtu 1450 -plan udp`
emits one newline-terminated JSON object. It uses the same validated sizing path
as serving, without reading credentials, opening sockets, starting a service or
constructing sessions. Invalid sizing, nonpositive session counts and arithmetic
overflow return an error without emitting a profile. Other serving flags are not
inputs to this mode. Consumers must bind the profile to the actual initial
session count, path MTU and migration plan used by the serving process.

| Field | Meaning |
| --- | --- |
| `schema_version` | Integer 1 |
| `max_sessions` | Positive configured session ceiling N |
| `path_mtu` | Validated initial planning MTU |
| `migration_plan` | Validated ordered class names, normalized by Class.String() |
| `message_bytes` | Validated initial carrier message ceiling M |
| `inner_payload_bytes` | Validated inner payload MTU I |
| `send_queue_packets` | Production send queue capacity Q |
| `send_buffer_slab_bytes` | Actual small send allocator slab size S |
| `pipe_inbox_packets` | Production Pipe inbox capacity D, derived from the token window |
| `pipe_buffer_slab_bytes` | Actual small Pipe allocator slab size P |
| `demux_buffer_bytes` | Actual per-split receive capacity C=max(4096,M) |
| `demux_packets_per_side` | Production admission capacity A per side |
| `demux_sides` | Number of constructed demux sides K |
| `batch_receive_slots` | Maximum batch-path demux receive staging slots B; a conservative allowance across supported builds, not the selected scalar path allocation |
| `send_payload_backing_per_session_bytes` | Q*max(S,I) |
| `pipe_payload_backing_per_session_bytes` | D*max(P,M) |
| `shared_demux_admitted_backing_bytes` | K*A*C |
| `shared_demux_staging_backing_bytes` | B*C, the maximum batch-path staging payload allowance |
| `configured_queue_payload_backing_bytes` | N*(send+pipe)+shared admitted+shared staging |
| `accounting_scope` | Literal `queue_payload_backing_only` |
| `not_included` | Explicit exclusions described below |

All byte calculations use checked uint64 products and sums. Numeric JSON fields
are integers. Consumers must parse them without floating-point rounding and
reject unsupported schema versions.

The total is requested payload backing for fully occupied configured queues
plus the maximum batch-path demux staging allowance despite the shorter scope
label. Scalar fallback uses fewer staging buffers, but receives the same
conservative allowance. The resources command does not open a socket or detect
which receive path will be selected. It is not current allocation, total required
memory, a process RSS ceiling, an installer budget, or a new resource limit.
Default buffer sizes and
queue policies are unchanged. Larger configured messages increase backing.

Excluded are queue and packet metadata; runtime, GC and retained pool storage;
session, device, cover and kernel storage; non-demux in-flight producer and
consumer buffers; retained and temporary send, receive and parser batch storage;
and future lifetime ceiling widening. The profile describes the initial selected
gateway configuration. Future code that widens its payload ceiling must revisit
this contract. No reserve policy or memory-limit enforcement follows from this
profile, and the existing installer memory-budget guard remains unresolved.
