defmodule SmashTest do
  use ExUnit.Case
  doctest Smash

  @test_alg :md5
  @test_data ["A", "B", "C", "D", "E"]
  @test_map_data [{"A", "a"}, {"B", "b"}, {"C", "c"}, {"D", "d"}]
  @large_test_data Enum.map(1..100, fn x -> "test_#{x}" end)
  @large_test_map_data Enum.map(1..100, fn x -> {"test_k_#{x}", "test_v_#{x}"} end)

  defp test_digests(data \\ @test_data) do
    Enum.map(data, &Smash.smash(@test_alg, &1))
  end

  defp test_digest_pairs(map_data \\ @test_map_data) do
    Enum.map(map_data, fn {k, v} ->
      {Smash.smash(@test_alg, k), Smash.smash(@test_alg, v)}
    end)
  end

  describe "basic hash functions" do

    test "smash produces different hashes for different inputs" do
      hash1 = Smash.smash(@test_alg, "test1")
      hash2 = Smash.smash(@test_alg, "test2")
      assert hash1 != hash2
    end

    test "smash uses sigil protection" do
      raw_hash = :crypto.hash(@test_alg, "test")
      smashed_hash = Smash.smash(@test_alg, "test")
      assert raw_hash != smashed_hash
    end

    test "smempty acts as the identity element with smappend" do
      empty = Smash.smempty(@test_alg)
      digest = Smash.smash(@test_alg, "test")

      assert Smash.smappend(@test_alg, empty, empty) == empty
      assert Smash.smappend(@test_alg, empty, digest) == digest
      assert Smash.smappend(@test_alg, digest, empty) == digest
    end

    test "smappend uses sigil protection" do
      digest1 = Smash.smash(@test_alg, "A")
      digest2 = Smash.smash(@test_alg, "B")

      smappended = Smash.smappend(@test_alg, digest1, digest2)
      concatenated_hash = Smash.smash(@test_alg, digest1 <> digest2)

      assert smappended != concatenated_hash
    end

    test "smfoldl on empty list returns empty digest" do
      result = Smash.smfoldl(@test_alg, [])
      expected = Smash.smempty(@test_alg)
      assert result == expected
    end

    test "smfoldl on single element returns that element" do
      digest = Smash.smash(@test_alg, "test")
      result = Smash.smfoldl(@test_alg, [digest])
      assert result == digest
    end
  end

  describe "digest utility functions" do
    test "digest_byte_size returns correct size" do
      size = Smash.digest_byte_size(@test_alg)
      digest = Smash.smash(@test_alg, "test")
      assert byte_size(digest) == size
    end

    test "digest_bit_size is 8 times byte size" do
      byte_size = Smash.digest_byte_size(@test_alg)
      bit_size = Smash.digest_bit_size(@test_alg)
      assert bit_size == byte_size * 8
    end

    test "test_digest_bit works correctly" do
      # Create a digest with known bit pattern
      digest = <<0b10101010>>

      assert Smash.test_digest_bit(digest, 0) == false  # LSB
      assert Smash.test_digest_bit(digest, 1) == true
      assert Smash.test_digest_bit(digest, 2) == false
      assert Smash.test_digest_bit(digest, 3) == true

      # TODO: Fix bug, then test out of bounds too.
      # assert Smash.test_digest_bit(digest, -1) == false
      # assert Smash.test_digest_bit(digest, 8) == false
    end
  end

  describe "set operations" do

    test "smash_set on empty list returns empty digest" do
      result = Smash.smash_set(@test_alg, [])
      expected = Smash.smempty(@test_alg)
      assert result == expected
    end

    test "smash_set on single digest returns that digest" do
      digest = Smash.smash(@test_alg, "test")
      result = Smash.smash_set(@test_alg, [digest])
      assert result == digest
    end

    test "smash_set is order independent" do
      digests = test_digests()
      shuffled = Enum.shuffle(digests)
      result1 = Smash.smash_set(@test_alg, digests)
      result2 = Smash.smash_set(@test_alg, shuffled)
      assert result1 == result2
    end

    test "smash_set on large list" do
      digests = test_digests(@large_test_data)
      result = Smash.smash_set(@test_alg, digests)
      assert result != Smash.smempty(@test_alg)
    end

  end

  describe "map operations" do
    test "smash_map on empty list returns empty digest" do
      result = Smash.smash_map(@test_alg, [])
      expected = Smash.smempty(@test_alg)
      assert result == expected
    end

    test "smash_map on single pair returns smappend of key and value" do
      key = Smash.smash(@test_alg, "key")
      value = Smash.smash(@test_alg, "value")

      result = Smash.smash_map(@test_alg, [{key, value}])
      expected = Smash.smappend(@test_alg, key, value)
      assert result == expected
    end

    test "smash_map on large list" do
      pairs = test_digest_pairs(@large_test_map_data)
      result = Smash.smash_map(@test_alg, pairs)
      assert result != Smash.smempty(@test_alg)
    end

  end


  describe "set proofs" do

    test "verify_set_proof on empty set" do
      proof = Smash.dissect_set(@test_alg, [])
      assert Smash.verify_set_proof(@test_alg, proof)
    end

    test "verify_set_proof on single element" do
      digest = Smash.smash(@test_alg, "test")
      proof = Smash.dissect_set(@test_alg, [digest])
      assert Smash.verify_set_proof(@test_alg, proof)
    end

    test "verify_set_proof on small set" do
      digests = test_digests(@test_data)
      proof = Smash.dissect_set(@test_alg, digests)
      assert Smash.verify_set_proof(@test_alg, proof)
    end

    test "verify_set_proof on large set" do
      digests = test_digests(@large_test_data)
      proof = Smash.dissect_set(@test_alg, digests)
      assert Smash.verify_set_proof(@test_alg, proof)
    end

  end

  describe "map proofs" do

    test "verify_map_proof on empty map" do
      proof = Smash.dissect_map(@test_alg, [])
      assert Smash.verify_map_proof(@test_alg, proof)
    end

    test "verify_map_proof on single pair" do
      key = Smash.smash(@test_alg, "key")
      value = Smash.smash(@test_alg, "value")
      proof = Smash.dissect_map(@test_alg, [{key, value}])
      assert Smash.verify_map_proof(@test_alg, proof)
      assert Smash.verify_map_proof(@test_alg, proof, [{key, value}])
    end

    test "verify_map_proof on small map" do
      pairs = test_digest_pairs(@test_map_data)
      proof = Smash.dissect_map(@test_alg, pairs)
      assert Smash.verify_map_proof(@test_alg, proof)
    end

    test "verify_map_proof on large map" do
      pairs = test_digest_pairs(@large_test_map_data)
      proof = Smash.dissect_map(@test_alg, pairs)
      assert Smash.verify_map_proof(@test_alg, proof)
    end

  end

end
