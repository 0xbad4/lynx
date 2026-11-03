# Memory model

**Buffers own. Views borrow.**

Every byte in the library lives in exactly one owned allocation. Everything else is a window over it. Parsing reads through windows and copies nothing. Producing bytes allocates once, at the exact size needed.

![Summary Diagram](./img/memory.png)

## Building blocks

| Piece | Role | Owns memory |
|---|---|---|
| `view` | A pointer and a length over existing bytes. Cheap to copy, never allocates, can carry an error. | no |
| `Buffer` | A shared allocation with an offset, a valid length and a capacity. | yes |
| Layer object | One unit of structure over bytes. Holds a view of its bytes and, only when it created them, the owner of those bytes. | sometimes |

> Layer objects link to the layer above and below through plain pointers. These links never own anything.

## Ownership rules

1. An allocation is released when its last owner is released.
2. A view is valid only while an owner of its bytes is alive.
3. A layer that borrows its bytes does not keep them alive. A layer that created its bytes does.
4. Pointers between layers are navigation only.
5. Capacity belongs to the allocation. A view or a serialized result covers only the valid bytes.

## Capture: zero-copy

- Received bytes land in one allocation sized to the capture length.
- The top-level object shares ownership of that allocation with an offset and a length.
- Each layer takes a view of everything after its parent's header. A layer reads its own header from the start of its view and passes the rest down.
- No header, field or payload is copied. Layers form a staircase of shrinking views over one allocation.
- Parents must outlive the layers derived from them.

## Craft: exact size

- Each layer allocates storage for its own header when it is created. These are separate allocations with separate addresses.
- Linking layers sets their pointers and trims the lower layer's view to its own header. Nothing moves.
- `size()` is the sum along the chain.
- Serializing allocates one buffer of exactly that size, then each layer writes itself into it in order.
- Fields that depend on later content, such as lengths and checksums, are rewritten in place once everything is laid out.
- Helper buffers used to compute those fields are temporary and released when the call returns.
- The finished buffer is sent. The caller can optionally receive shared ownership of it.

## Buffer operations

| Operation | Effect |
|---|---|
| `alloc(n)` | New zero-filled allocation of exactly `n` bytes, valid length 0. |
| `reserve(n)` | Advances the valid length by `n` and returns writable memory. |
| `write(src, n)` | Copies `n` bytes at the valid length and advances it. |
| `patch(pos, src, n)` | Overwrites bytes at `pos` without moving the valid length. |
| `wrap(owner, off, len)` | Read-only window over an existing allocation. Capacity equals length. |

A buffer never grows. Writes past capacity fail and set the error state.

## Growable containers

Containers that change size during their life follow the vector model.

- **Size and capacity are separate.** The view covers exactly the valid bytes. Spare capacity is never serialized.
- **Appending within capacity moves nothing.** Pointers and views into the container stay valid.
- **Growth is geometric.** When capacity runs out, capacity at least doubles, so appends cost amortized constant time.
- **Reallocation invalidates everything** that points into the container. Removal invalidates from the first removed element onward.
- **Capacity is kept.** Removal and clearing keep capacity. `shrink_to_fit` releases it.
- **`reserve` preallocates** so later appends never allocate.
- **Borrowed until mutated.** A container built over existing bytes borrows them. The first mutation copies them into owned storage, so the source is never modified.
- **Value semantics.** A copy owns an independent copy of the bytes. A move transfers storage and leaves the source empty.
- **Failure is non-destructive.** Mutators report an error and leave the container unchanged.

## Lifetimes and invalidation

| Event | What becomes invalid |
|---|---|
| Last owner released | Every view over that allocation |
| Container reallocates | All views and pointers into the container |
| Container removes elements | Views at or after the first removed element |
| Container appends within capacity | Nothing |
| Layers unlinked | The links only, never the bytes |

## Rules of thumb

- Borrow to read. Allocate to produce.
- One allocation per serialized packet.
- Never keep a view longer than its owner.
- Patch in place instead of rebuilding.
- Check the error state once at the top. The first failure is the one reported.