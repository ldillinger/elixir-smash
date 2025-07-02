# SMASH - (S)parse (M)erkle H(ashing)

This library implements a sparse merkle hash / tree using a unital magma hash technique. This is similar to a monoid, but slightly weaker, without the property of associativity. The resulting implementation is a 'natural' implementation of sparse merkle trees, and has a number of desirable properties, including automatic sparsity contracture, and 2nd-preimage resistance.

## Features

- **Natural Sparsity**: The unital magma hash naturally encodes the isomorphism between sparse and non-sparse merkle trees
- **Proof Generation**: Create and verify Merkle proofs for both sets and maps
- **Preimage Attack Protection**: Sigil-based protection prevents crafted input attacks
- **Flexible Hash Algorithms**: Support for any hash algorithm from Erlang's `:crypto` module

## Installation

Add `smash` to your list of dependencies in `mix.exs`:

> TODO: This isn't uploaded to a package manager / yet so this probably needs
> a reference to the github repo to make it work

```elixir
def deps do
  [
    {:smash, "~> 0.1.0"}
  ]
end
```

## Quick Start

```elixir
# Choose a hash algorithm
alg = :sha256

# Hash some data with sigil protection
digest_a = Smash.smash(alg, "Hello")
digest_b = Smash.smash(alg, "World")

# Create a set hash
set_hash = Smash.smash_set(alg, [digest_a, digest_b])

# Generate a proof
proof = Smash.dissect_set(alg, [digest_a, digest_b])

# Verify the proof
Smash.verify_set_proof(alg, proof) # => true

# Verify the proof of specific leaves
Smash.verify_set_proof(alg, proof, [digest_a])
```

## Testing

Run the test suite:

```bash
mix test
```

The module includes comprehensive tests covering:
- Basic hash operations and sigil protection
- Set and map operations with various data sizes
- Proof generation and verification
- Edge cases and error conditions

## Development

I'm working on it! Future enhancements may include:

- `Smashable` protocol for arbitrary data structures
- Tree manipulation operations (insertion, deletion, merging)
- Differential operations and subproofs
- Performance optimizations
- Integration with FROG (Fragmented Object Graph) system

## Security Considerations

- Empty digest uses all-zeros pattern (safe with collision-resistant hashes)
- Uses sigil protection to prevent second-preimage attacks
- Requires collision-resistant hash functions (e.g., SHA-256, SHA-3)
- Not compatible with standard naive Merkle tree implementations due to sigil protection

## License

BSD-3 License
