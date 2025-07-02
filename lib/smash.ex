# Smashing Frogs - Sparse Merkle Hashing / FRagmented Object Graphs
defmodule Smash do

    @moduledoc """
    This module implements a sparse merkle hash / tree using a unital magma hash
    technique. This is similar to a monoid, but slightly weaker, without the
    property of associativity.

    The resulting implementation is a 'natural' implementation of sparse merkle
    trees, and has a number of desirable properties, including automatic
    sparsity contracture, and 2nd-preimage resistance. The implementation is
    deliberately simple for illustration purposes, but is amenable to further
    optimization.

    The implementation is 'natural' in that the sparsity of the tree directly
    arises from the automatic contracture of nodes due to the empty digest's
    role as the identity element in the binary operation for combining digests.

    We guard against 2nd-preimage attacks by using sigils to protect the input
    and ensure that it is impossible to produce the same digest from raw input
    as from combining digests, even with carefully-crafted inputs.
    In other words:
        smash("A") != hash("A")
    and:
        smappend(smash("A"), smash("B")) !=smash(smash("A") <> smash("B"))
    As a consequence, smashing produces a different digest from the original
    hashing algorithm, and these merkle trees are not compatible with standard
    naive implementations.

    For simplicity, the empty / identity digest is the zeroes digest. We could
    use the hash of the empty string (which is otherwise unobtainable due to the
    use of sigils), or make magma digests an optional type with nil as the empty
    digest. However, this makes the empty digest harder to recognize or take up
    extra space. Since we expect to use cryptographic hashes with collision
    resistance, we can use the zeroes digest safely because it requires finding
    a collision in the hash function to exploit, which is infeasible, and easily
    managed by the use of an appropriate hash algorithm eg :sha3_256.

    This implementation operates directly on digests; the means by which they
    are generated is up to the user. Further work on this library would include
    a Smashable protocol for smashing arbitrary data, as well as operations for
    insertion, deletion, diffing, merging, and subproofs.
    """

    import Bitwise

    #
    # Hash types
    #

    @type hashalg() :: :crypto.hashs()
    @type digest() :: binary()
    @type digest_pair() :: {digest(), digest()}

    @hash_algorithms :crypto.supports(:hashs)

    @doc """
    Supported hash algorithms.
    """
    @spec hash_algorithms() :: [hashalg()]
    def hash_algorithms, do: @hash_algorithms

    #
    # Digest functions
    #

    @doc """
    The digest size in bytes for a given hash algorithm.
    """
    @spec digest_byte_size(hashalg()) :: integer()
    def digest_byte_size(alg) do
        :crypto.hash_info(alg)[:size]
    end


    @doc """
    The digest size in bits for a given hash algorithm.
    """
    @spec digest_bit_size(hashalg()) :: integer()
    def digest_bit_size(alg) do
        digest_byte_size(alg) * 8
    end

    @doc """
    Test whether the nth bit of a digest is set. Assumes big-endian / MS order.
    """
    @spec test_digest_bit(digest(), integer()) :: boolean()
    # TODO: Fix bug where the byte is out of range, probably move the cond
    # to the top level.
    def test_digest_bit(digest, n) when is_binary(digest) do
        q = div(n, 8)
        r = rem(n, 8)
        # NOTE: Since we have a digest, we can use its size directly instead
        # of having to know the algorithm.
        byte = :binary.at(digest, (byte_size(digest) - 1) - q)
        cond do
            n < 0 -> false
            n > (bit_size(digest) - 1) -> false
            true -> (byte &&& (1 <<< r)) > 0
        end
    end

    #
    # Unital magma hashing
    #

    @smash_sigil "#"

    @doc """
    Raw hash function for sparse merkle hashing.

    Guards input with a sigil to prevent preimage attacks.
    """
    @spec smash(hashalg(), binary()) :: digest()
    def smash(alg, data) do
        :crypto.hash(alg, @smash_sigil <> data)
    end

    @doc """
    The empty digest for a given hash algorithm.

    This is the magma's identity element.

    This implementation uses the zeroes digest as the empty digest for
    simplicity. We could use the hash of the empty string, or make digest an
    optional type with nil for the empty digest. However, the all-zeroes digest
    is easily recognizable, and is otherwise unobtainable due to the use of
    sigils, assuming a collision-resistant cryptographic hash function is used.
    """
    @spec smempty(hashalg()) :: digest()
    def smempty(alg) do
        # NOTE: We could memoize this
        n = digest_byte_size(alg)
        :binary.copy(<<0>>,n)
    end

    @smappend_sigil "$"
    @smappend_separator "+"

    @doc """
    Combine two digests.

    This is the magma's binary operation.

    Guards input with sigils to prevent preimage attacks.
    """
    @spec smappend(hashalg(), digest(), digest()) :: digest()
    def smappend(alg, a, b) do
        empty = smempty(alg)
        cond do
            a == empty -> b
            b == empty -> a
            true ->
                smash(
                    alg,
                    @smappend_sigil <> a <> @smappend_separator <> b
                )
        end
    end

    @doc """
    Left fold over a list of digests using the empty digest and the magma's
    binary operation.
    """
    @spec smfoldl(hashalg(), [digest()]) :: digest()
    def smfoldl(alg, digests) do
        List.foldl(
            digests,
            smempty(alg),
            fn(a, b) -> smappend(alg, a, b) end
        )
    end

    #
    # Smash functions
    #

    @doc """
    Calculate the merkle hash of a set of digests.
    """
    @spec smash_set(hashalg(), [digest()]) :: digest()
    def smash_set(alg, digests) do
        smash_set(alg, digests, digest_bit_size(alg) - 1)
    end
    defp smash_set(alg, [], _n), do: smempty(alg)
    defp smash_set(_alg, [x], _n), do: x
    # Deduplication - Elixir can use pattern matching to check for equality :)
    defp smash_set(alg, [x, x | xs], n), do: smash_set(alg, [x | xs], n)
    defp smash_set(alg, xs, n) do
        {l, r} = Enum.split_with(xs, fn x -> not test_digest_bit(x, n) end)
        ld = smash_set(alg, l, n - 1)
        rd = smash_set(alg, r, n - 1)
        smappend(alg, ld, rd)
    end

    @doc """
    Calculate the merkle hash of a set of key-value digest pairs.
    """
    @spec smash_map(hashalg(), [digest_pair()]) :: digest()
    def smash_map(alg, digest_pairs) do
        smash_map(alg, digest_pairs, digest_bit_size(alg) - 1)
    end
    defp smash_map(alg, [], _n), do: smempty(alg)
    defp smash_map(alg, [{k,v}], _n), do: smappend(alg, k, v)
    # Deduplication - Elixir can use pattern matching to check for equality :)
    defp smash_map(alg, [{k,v}, {k,_} | xs], n), do: smash_map(alg, [{k,v} | xs], n)
    defp smash_map(alg, xs, n) do
        {l, r} = Enum.split_with(xs, fn({k,_v}) -> not test_digest_bit(k, n) end)
        ld = smash_map(alg, l, n - 1)
        rd = smash_map(alg, r, n - 1)
        smappend(alg, ld, rd)
    end

    #
    # Dissection functions
    #

    # TODO: Could generalize the proof type, set is just map<k,nil>
    # @type proof(leaf) :: {top_digest(), evidence_map(), %{leaf_digest() => leaf}}
    # Then we could unify the set and map proof implementations

    # NOTE: The prefix is only necessary for navigating the proof; that entropy
    # is already included via the leaf digests.
    @type prefix() :: [boolean()] # Mmmm probably a more elixir-y way to do this

    @type top_digest() :: digest()
    @type evidence() :: {prefix(), digest(), digest()}
    @type evidence_map() :: %{ digest() => evidence() }

    # NOTE: A list instead of set because Dialyzer complains about opaque types
    # if I use MapSet.t(digest())
    @type leaf_set() :: [digest()]
    @type set_proof() :: {top_digest(), evidence_map(), leaf_set()}

    @doc """
    Calculate the full merkle proof of a set of digests.

    The proof is of a format suitable for trimming to a partial proof of select
    leaves.
    """
    @spec dissect_set(hashalg(), [digest()]) :: set_proof()
    # NOTE: Prefix is probably a bit of a misnomer - its more of a relative
    # prefix or span. The intent is that the prefix or span captures the path
    # left vs right for the sparse nodes in th tree that have been automatically
    # contracted due to the empty digest's role as the identity element.
    # As an example: Consider the binary digests 0000 and 0001, and the merkle
    # tree that would be generated - it would consist of a single piece of
    # evidence, with the prefix 000, and the left and right digests 0000 and
    # 0001. When generating this prefix, it should be relative to the current
    # bit index n, and should contain the run of bits that are the same in both
    # digests, with n being decremented appropriately.
    #
    # This is a bit of a hack, but it works for now.
    #
    # Also note that for efficiency, we build the prefix list in reverse order,
    # and then reverse it when assigning it to evidence.
    def dissect_set(alg, digests) do
        dissect_set(alg, digests, digest_bit_size(alg) - 1, [])
    end
    defp dissect_set(alg, [], _n, _prefix), do: {smempty(alg), %{}, []}
    defp dissect_set(_algorithm, [x], _n, _prefix), do: {x, %{}, [x]}
    defp dissect_set(alg, [x, x | xs], n, prefix) do
        dissect_set(alg, [x | xs], n, prefix)
    end
    defp dissect_set(alg, xs, n, prefix) do
        {fs, ts} = Enum.split_with(xs, fn x -> not test_digest_bit(x, n) end)
        case {fs, ts} do
            {[], ts} ->
                dissect_set(alg, ts, n - 1, [true | prefix])
            {fs, []} ->
                dissect_set(alg, fs, n - 1, [false | prefix])
            {fs, ts} ->
                {l, le, ll} = dissect_set(alg, fs, n - 1, [])
                {r, re, rl} = dissect_set(alg, ts, n - 1, [])
                h = smappend(alg, l, r)
                {
                    h,
                    Map.put(Map.merge(le, re), h, {Enum.reverse(prefix), l, r}),
                    ll ++ rl
                }
        end
    end

    @type map_proof() :: {top_digest(), evidence_map(), leaf_map()}
    @type leaf_map() :: %{ digest() => digest_pair() }

    @doc """
    Calculate the full merkle proof of a set of key-value digest pairs.

    The proof is of a format suitable for trimming to a partial proof of select
    leaves.
    """
    @spec dissect_map(hashalg(), [digest_pair()]) :: map_proof()
    def dissect_map(alg, digest_pairs) do
        dissect_map(alg, digest_pairs, digest_bit_size(alg) - 1, [])
    end
    defp dissect_map(alg, [], _n, _prefix), do: {smempty(alg), %{}, %{}}
    defp dissect_map(alg, [{k,v}], _n, _prefix) do
        h = smappend(alg, k, v)
        {h, %{}, %{h => {k,v}}}
    end
    defp dissect_map(alg, [{k,v}, {k,_} | xs], n, prefix) do
        dissect_map(alg, [{k,v} | xs], n, prefix)
    end
    defp dissect_map(alg, xs, n, prefix) do
        {fs, ts} = Enum.split_with(xs, fn({k,_v}) -> not test_digest_bit(k, n) end)
        case {fs, ts} do
            {[], ts} ->
                dissect_map(alg, ts, n - 1, [true | prefix])
            {fs, []} ->
                dissect_map(alg, fs, n - 1, [false | prefix])
            {fs, ts} ->
                {l, le, ll} = dissect_map(alg, fs, n - 1, [])
                {r, re, rl} = dissect_map(alg, ts, n - 1, [])
                h = smappend(alg, l, r)
                {
                    h,
                    Map.put(Map.merge(le, re), h, {Enum.reverse(prefix), l, r}),
                    Map.merge(ll, rl)
                }
        end
    end

    #
    # Proof and evidence functions
    #

    # TODO: Functions for insertion, deletion, pruning to subproofs, etc.

    @doc """
    Verify that evidence's prefix bits match a leaf digest's bits for a given
    position.
    """
    @spec verify_prefix(prefix(), digest(), integer()) :: {:ok, integer()} | {:error}
    # NOTE: This error case should never occur for well-formed proofs - that is,
    # the cumulative prefix should never be longer than the digest. However, for
    # sanity and to ensure malformed proofs terminate, we include this first case.
    defp verify_prefix([], _leaf, n) when n < 0, do: {:error}
    defp verify_prefix([], _leaf, n), do: {:ok, n}
    defp verify_prefix([x | xs], leaf, n) do
        if test_digest_bit(leaf, n) == x do
            verify_prefix(xs, leaf, n - 1)
        else
            {:error}
        end
    end

    @doc """
    Verify that evidence of a given target digest is correct, using a given key
    digest to navigate the proof. Note the difference between evidence-of and
    evidence-for is a matter of perspective - evidence-of below is evidence-for
    above.

    For set proofs, 'key' and 'target' should be the same leaf digest. For map
    proofs, 'key' is the key digest and 'target' is smappend(key, value).
    'current' should initially be the top hash.

    NOTE: This seems to behave 'improperly' in that eg if we try to verify an
    intermediate hash (such as the top hash) as a target, it will return true
    without checking the evidence for that hash. This is because it is
    intented to be used for verifying leaves, which do not have evidence
    beneath them, and are verified elsewhere. For example, take the singleton
    set of digests { A } - the only hash in the set is A, so the top hash is
    also A, and so requires no evidence. Hence, this actually behaves properly.

    See verify_set_proof and verify_map_proof for usage.
    """
    @spec verify_evidence_map(hashalg(), evidence_map(), digest(), digest(), digest(), integer()) :: boolean()
    defp verify_evidence_map(_algorithm, _evidence, _key, target, target, _n), do: true
    defp verify_evidence_map(algorithm, evidence, key, target, current, n) do
        case Map.get(evidence, current) do
            nil ->
                IO.puts("No evidence for #{pretty_digest(:base16, target)} under #{pretty_digest(:base16, current)}")
                false
            {prefix, l, r} ->
                case verify_prefix(prefix, key, n) do
                    {:ok, nn } ->
                        case smappend(algorithm, l, r) do
                            ^current ->
                                next = if test_digest_bit(key, nn), do: r, else: l
                                verify_evidence_map(algorithm, evidence, key, target, next, nn - 1)
                            _ ->
                                IO.puts("Mismatch for #{pretty_digest(:base16, current)}")
                                false
                        end
                    {:error} ->
                        IO.puts("Prefix mismatch for #{pretty_digest(:base16, current)}")
                        false
                end
        end
    end

    @doc """
    Verifies (all of) the leaves in a set proof.

    If supplied, targets should be a subset of leaves, and will default to the
    whole set of available leaves if not provided.
    Note that the proof may be a partial proof.

    TODO: Return :valid | :invalid | :incomplete to disambiguate validation mismatch from missing evidence
    """
    @spec verify_set_proof(hashalg(), set_proof(), [digest()]) :: boolean()
    def verify_set_proof(algorithm, {top, evidence, leaves}) do
        verify_set_proof(algorithm, {top, evidence, leaves}, leaves)
    end
    def verify_set_proof(algorithm, {top, evidence, leaves}, targets) do
        Enum.all?(targets, fn(target) ->
            has_evidence_chain = verify_evidence_map(
                algorithm,
                evidence,
                target,
                target,
                top,
                digest_bit_size(algorithm) - 1
            )
            is_leaf = Enum.member?(leaves, target)
            has_evidence_chain and is_leaf
        end)
    end

    @doc """
    Verifies (all of) the leaves in a map proof.

    If supplied, targets should be a subset of leaves, and will default to the
    whole set of available leaves if not provided.
    Note that the proof may be a partial proof.

    Note that unlike verify_set_proof, this function takes key-value digest
    pairs instead of digests.
    """
    @spec verify_map_proof(hashalg(), map_proof(), [digest_pair()]) :: boolean()
    def verify_map_proof(algorithm, {top, evidence, leaves}) do
        verify_map_proof(algorithm, {top, evidence, leaves}, Map.values(leaves))
    end
    def verify_map_proof(algorithm, {top, evidence, leaves}, targets) do
        Enum.all?(targets, fn({k,v}) ->
            target = smappend(algorithm, k, v)
            has_evidence_chain = verify_evidence_map(
                algorithm,
                evidence,
                k,
                target,
                top,
                digest_bit_size(algorithm) - 1
            )
            is_leaf = case Map.get(leaves, target) do
                {^k,^v} ->
                    true
                nil ->
                    IO.puts("No leaf evidence for #{pretty_digest(:base16, target)}")
                    false
                _ ->
                    IO.puts("Leaf evidence mismatch for #{pretty_digest(:base16, target)}")
                    false
            end
            has_evidence_chain and is_leaf
        end)
    end

    #
    # Pretty printing functions
    #

    @type digest_format() :: :base16 | :base64

    @pretty_digest_format :base16

    @spec pretty_digest(digest_format(), digest()) :: String.t()
    def pretty_digest(format \\ @pretty_digest_format, digest) do
        case format do
            :base16 -> Base.encode16(digest, case: :lower)
            :base64 -> Base.encode64(digest)
        end
        # TODO: Probably should cast to String
    end

    @spec print_digest(digest_format(), digest()) :: :ok
    def print_digest(format \\ @pretty_digest_format, digest) do
        IO.puts(pretty_digest(format, digest))
    end

    # Eh, this is hacky but its for debugging
    # NOTE: Avoiding interpolation because we're using # a lot
    @spec pretty_evidence(evidence()) :: String.t()
    def pretty_evidence({prefix, l, r}) do
        prefix_str = Enum.map_join(prefix, fn(b) -> if b, do: "1", else: "0" end)
        ":[" <> prefix_str <> "]\n"
            <> "    $ #" <> pretty_digest(:base16, l) <> "\n"
            <> "    + #" <> pretty_digest(:base16, r) <> "\n"
    end

    @spec pretty_set_proof(set_proof()) :: String.t()
    def pretty_set_proof({top, evidence, leaves}) do
        top_str = "#" <> pretty_digest(:base16, top) <> "\n"
        evi_str = Enum.map_join(evidence, fn({k,v}) ->
            "#" <> pretty_digest(:base16, k) <> " = " <> pretty_evidence(v)
        end)
        leaves_str = Enum.map_join(leaves, fn(d) ->
            "#" <> pretty_digest(:base16, d) <> "\n"
        end)
        "Top hash:\n" <> top_str <> "Evidence:\n" <> evi_str <> "Leaves:\n" <> leaves_str
    end

    @spec pretty_map_proof(map_proof()) :: String.t()
    def pretty_map_proof({top, evidence, leaves}) do
        top_str = "#" <> pretty_digest(:base16, top) <> "\n"
        evi_str = Enum.map_join(evidence, fn({k,v}) ->
            "#" <> pretty_digest(:base16, k) <> " = " <> pretty_evidence(v)
        end)
        leaves_str = Enum.map_join(leaves, fn({k,{l,r}}) ->
            "#" <> pretty_digest(:base16, k) <> " = \n    ( #" <> pretty_digest(:base16, l) <> "\n    , #" <> pretty_digest(:base16, r) <> ")\n"
        end)
        "Top hash:\n" <> top_str <> "Evidence:\n" <> evi_str <> "Leaves:\n" <> leaves_str
    end

    #
    # Testing / debugging functions
    # See test/smash_test.exs for more comprehensive tests

    @spec test_dissect_set(hashalg(), [binary()]) :: :ok
    def test_dissect_set(algorithm, values \\ ["A","B","C","D"]) do
        digests = Enum.map(values, fn(x) -> smash(algorithm, x) end)
        proof = dissect_set(algorithm, digests)
        IO.puts(pretty_set_proof(proof))
        a = smash(algorithm, "A")
        z = smash(algorithm, "Z")
        bang = smash(algorithm, "!")
        IO.puts("Testing presence of \"A\": #{verify_set_proof(algorithm, proof, [a])}")
        IO.puts("Testing presence of \"Z\": #{verify_set_proof(algorithm, proof, [z])}")
        IO.puts("Testing presence of \"!\": #{verify_set_proof(algorithm, proof, [bang])}")
        :ok
    end

    @spec test_dissect_map(hashalg(), %{binary() => binary()}) :: :ok
    def test_dissect_map(algorithm, values \\ %{{"A","a" }, {"B","b"}, {"C", "c"}, {"D","d"}}) do
        digest_pairs = Enum.map(values, fn({x,y}) -> {smash(algorithm, x), smash(algorithm, y)} end)
        proof = dissect_map(algorithm, digest_pairs)
        IO.puts(pretty_map_proof(proof))
        aa = {smash(algorithm, "A"), smash(algorithm, "a")}
        zz = {smash(algorithm, "Z"), smash(algorithm, "z")}
        bang = {smash(algorithm, "!"), smash(algorithm, "?")}
        IO.puts("Testing presence of {\"A\": \"a\"}: #{verify_map_proof(algorithm, proof, [aa])}")
        IO.puts("Testing presence of {\"Z\": \"z\"}: #{verify_map_proof(algorithm, proof, [zz])}")
        IO.puts("Testing presence of {\"!\": \"?\"}: #{verify_map_proof(algorithm, proof, [bang])}")
        :ok
    end

    def test_smashing() do
        alg = :md5
        upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" |> String.split("", trim: true)
        lower = "abcdefghijklmnopqrstuvwxyz" |> String.split("", trim: true)
        test_dissect_set(alg, upper)
        test_dissect_map(alg, Map.new(Enum.zip(upper, lower)))
    end

    #
    # EXPERIMENTAL - BEYOND HERE LIES CONCEPTS UNFULFILLED - IGNORE THEM
    #

    # TODO: ...
    # defprotocol Smashable do
    #     @spec to_frog(term()) :: Frog.frog()
    #     def to_frog(term)
    # end

    # FROG - FRagmented Object Graph
    # In Haskell:
    # type FrogObjKey = String
    # type FrogArrPos = Int
    # data FrogIdx
    #     = FrogObjKey FrogObjKey
    #     | FrogArrPos FrogArrPos
    # data Frog a r
    #     = FrogObj (Map FrogObjKey r)
    #     | FrogArr (Vector r)
    #     | FrogLeaf a
    # data FrogPrim
    #     = FrogNull
    #     | FrogBool Bool
    #     | FrogInt Int
    #     | FrogFloat Float
    #     | FrogString String
    defmodule Frog do

        @type obj_key() :: String.t()
        defguard is_obj_key(t) when is_binary(t)

        @type arr_pos() :: non_neg_integer() # Ugh, need @type natural() :: non_neg_integer()
        defguard is_arr_pos(t) when is_integer(t) and t >= 0

        @type idx() :: obj_key() | arr_pos()
        defguard is_idx(t) when is_obj_key(t) or is_arr_pos(t)

        @type path() :: [idx()]

        @type primitive() :: nil | boolean() | integer() | float() | String.t()
        @spec is_primitive(any()) ::
                {:__block__ | {:., [], [:erlang | :orelse, ...]}, [{:generated, true}],
                 [{:= | {any(), any(), any()}, list(), [...]}, ...]}
        defguard is_primitive(t) when is_nil(t) or is_boolean(t) or is_integer(t) or is_float(t) or is_binary(t)

        @type t(a, r) :: %{ obj_key() => r } | [r] | a
        @type fix_t(a) :: t(a, fix_t(a))
        @type frag_t(a) :: t(a, Smash.digest())

        @type frog() :: fix_t(primitive())
        @type froglet() :: frag_t(primitive())

        @spec smash_idx(Smash.hashalg(), idx()) :: Smash.digest()
        defp smash_idx(algorithm, k) when is_obj_key(k) do
            Smash.smfoldl(algorithm, [Smash.smash(algorithm, "obj_key"), Smash.smash(algorithm, k)])
        end
        defp smash_idx(algorithm, n) when is_arr_pos(n) do
            Smash.smfoldl(algorithm, [Smash.smash(algorithm, "arr_pos"), Smash.smash(algorithm, n)])
        end

        @spec smash_path(Smash.hashalg(), path()) :: Smash.digest()
        defp smash_path(algorithm, path) do
            Smash.smfoldl(algorithm, Enum.map(path, fn x -> smash_idx(algorithm, x) end))
        end

        # TODO

        def dissect(algorithm, frog) do

        end

    end

end
