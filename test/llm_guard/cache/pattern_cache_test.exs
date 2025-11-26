defmodule LlmGuard.Cache.PatternCacheTest do
  use ExUnit.Case, async: false

  alias LlmGuard.Cache.PatternCache

  setup do
    # Start cache for each test
    {:ok, _pid} = start_supervised({PatternCache, []})
    :ok
  end

  describe "pattern caching" do
    test "caches and retrieves compiled patterns" do
      pattern = ~r/test pattern/i
      assert :ok = PatternCache.put_pattern("test_pattern", pattern)
      assert {:ok, ^pattern} = PatternCache.get_pattern("test_pattern")
    end

    test "returns error for uncached pattern" do
      assert :error = PatternCache.get_pattern("nonexistent")
    end

    test "handles concurrent pattern access" do
      pattern = ~r/concurrent/i
      PatternCache.put_pattern("concurrent", pattern)

      tasks =
        for _ <- 1..100 do
          Task.async(fn ->
            PatternCache.get_pattern("concurrent")
          end)
        end

      results = Task.await_many(tasks)
      assert Enum.all?(results, fn result -> result == {:ok, pattern} end)
    end

    test "caches multiple patterns independently" do
      pattern1 = ~r/pattern1/i
      pattern2 = ~r/pattern2/i

      PatternCache.put_pattern("p1", pattern1)
      PatternCache.put_pattern("p2", pattern2)

      assert {:ok, ^pattern1} = PatternCache.get_pattern("p1")
      assert {:ok, ^pattern2} = PatternCache.get_pattern("p2")
    end

    test "overwrites existing pattern" do
      pattern1 = ~r/old/i
      pattern2 = ~r/new/i

      PatternCache.put_pattern("test", pattern1)
      PatternCache.put_pattern("test", pattern2)

      assert {:ok, ^pattern2} = PatternCache.get_pattern("test")
    end
  end

  describe "result caching" do
    test "caches and retrieves detection results" do
      result = {:detected, %{confidence: 0.95}}
      input_hash = PatternCache.hash_input("test input")

      PatternCache.put_result(input_hash, "prompt_injection", result, 300)
      # Give async operation time to complete
      Process.sleep(10)

      assert {:ok, ^result} = PatternCache.get_result(input_hash, "prompt_injection")
    end

    test "returns error for uncached result" do
      assert :error = PatternCache.get_result("nonexistent", "detector")
    end

    test "respects TTL expiration" do
      result = {:safe, %{}}
      input_hash = PatternCache.hash_input("test")

      # Cache with 1 second TTL
      PatternCache.put_result(input_hash, "detector", result, 1)
      Process.sleep(10)

      # Should be cached
      assert {:ok, ^result} = PatternCache.get_result(input_hash, "detector")

      # Wait for expiration
      Process.sleep(1100)

      # Should be expired
      assert :error = PatternCache.get_result(input_hash, "detector")
    end

    test "different detectors can cache same input" do
      input_hash = PatternCache.hash_input("shared input")
      result1 = {:detected, %{confidence: 0.9}}
      result2 = {:safe, %{}}

      PatternCache.put_result(input_hash, "detector1", result1, 300)
      PatternCache.put_result(input_hash, "detector2", result2, 300)
      Process.sleep(10)

      assert {:ok, ^result1} = PatternCache.get_result(input_hash, "detector1")
      assert {:ok, ^result2} = PatternCache.get_result(input_hash, "detector2")
    end

    test "handles concurrent result access" do
      input_hash = PatternCache.hash_input("concurrent")
      result = {:safe, %{}}
      PatternCache.put_result(input_hash, "detector", result, 300)
      Process.sleep(10)

      tasks =
        for _ <- 1..100 do
          Task.async(fn ->
            PatternCache.get_result(input_hash, "detector")
          end)
        end

      results = Task.await_many(tasks)
      assert Enum.all?(results, fn r -> r == {:ok, result} end)
    end
  end

  describe "hash_input/1" do
    test "generates consistent hashes" do
      input = "test input"
      hash1 = PatternCache.hash_input(input)
      hash2 = PatternCache.hash_input(input)

      assert hash1 == hash2
      assert is_binary(hash1)
      assert String.length(hash1) == 64
    end

    test "generates different hashes for different inputs" do
      hash1 = PatternCache.hash_input("input1")
      hash2 = PatternCache.hash_input("input2")

      assert hash1 != hash2
    end

    test "generates deterministic hashes" do
      input = "deterministic test"
      expected = PatternCache.hash_input(input)

      # Hash multiple times
      hashes = for _ <- 1..10, do: PatternCache.hash_input(input)

      assert Enum.all?(hashes, fn hash -> hash == expected end)
    end
  end

  describe "cache management" do
    test "clear_results removes all results" do
      result = {:safe, %{}}

      for i <- 1..5 do
        hash = PatternCache.hash_input("input#{i}")
        PatternCache.put_result(hash, "detector", result, 300)
      end

      Process.sleep(10)

      assert :ok = PatternCache.clear_results()

      for i <- 1..5 do
        hash = PatternCache.hash_input("input#{i}")
        assert :error = PatternCache.get_result(hash, "detector")
      end
    end

    test "clear_results does not affect patterns" do
      pattern = ~r/test/i
      PatternCache.put_pattern("test", pattern)

      PatternCache.clear_results()

      assert {:ok, ^pattern} = PatternCache.get_pattern("test")
    end

    test "clear_all removes patterns and results" do
      pattern = ~r/test/i
      result = {:safe, %{}}
      hash = PatternCache.hash_input("input")

      PatternCache.put_pattern("test", pattern)
      PatternCache.put_result(hash, "detector", result, 300)
      Process.sleep(10)

      assert :ok = PatternCache.clear_all()

      assert :error = PatternCache.get_pattern("test")
      assert :error = PatternCache.get_result(hash, "detector")
    end

    test "enforces max_results limit" do
      # Start cache with small limit
      stop_supervised(PatternCache)
      {:ok, _pid} = start_supervised({PatternCache, max_results: 5})

      # Add more results than the limit
      for i <- 1..10 do
        hash = PatternCache.hash_input("input#{i}")
        PatternCache.put_result(hash, "detector", {:safe, %{}}, 300)
      end

      Process.sleep(50)

      # Cache should not exceed max_results
      stats = PatternCache.stats()
      assert stats.result_count <= 5
    end
  end

  describe "stats/0" do
    test "returns cache statistics" do
      stats = PatternCache.stats()

      assert Map.has_key?(stats, :pattern_count)
      assert Map.has_key?(stats, :result_count)
      assert Map.has_key?(stats, :pattern_hits)
      assert Map.has_key?(stats, :pattern_misses)
      assert Map.has_key?(stats, :result_hits)
      assert Map.has_key?(stats, :result_misses)
      assert Map.has_key?(stats, :hit_rate)
    end

    test "tracks pattern hits and misses" do
      pattern = ~r/test/i
      PatternCache.put_pattern("test", pattern)

      # Hit
      PatternCache.get_pattern("test")
      # Miss
      PatternCache.get_pattern("nonexistent")

      stats = PatternCache.stats()
      assert stats.pattern_hits >= 1
      assert stats.pattern_misses >= 1
    end

    test "tracks result hits and misses" do
      hash = PatternCache.hash_input("test")
      PatternCache.put_result(hash, "detector", {:safe, %{}}, 300)
      Process.sleep(10)

      # Hit
      PatternCache.get_result(hash, "detector")
      # Miss
      PatternCache.get_result("nonexistent", "detector")

      stats = PatternCache.stats()
      assert stats.result_hits >= 1
      assert stats.result_misses >= 1
    end

    test "calculates hit rate correctly" do
      # Start fresh
      PatternCache.clear_all()

      pattern = ~r/test/i
      PatternCache.put_pattern("test", pattern)

      # 3 hits
      PatternCache.get_pattern("test")
      PatternCache.get_pattern("test")
      PatternCache.get_pattern("test")

      # 1 miss
      PatternCache.get_pattern("nonexistent")

      stats = PatternCache.stats()
      # Hit rate should be 3/4 = 0.75
      assert_in_delta stats.hit_rate, 0.75, 0.01
    end

    test "hit rate is 0.0 with no requests" do
      # Fresh cache
      stop_supervised(PatternCache)
      {:ok, _pid} = start_supervised({PatternCache, []})

      stats = PatternCache.stats()
      assert stats.hit_rate == 0.0
    end
  end

  describe "expiration and cleanup" do
    test "automatically cleans up expired entries" do
      # Start cache with fast cleanup
      stop_supervised(PatternCache)
      {:ok, _pid} = start_supervised({PatternCache, cleanup_interval: 100})

      hash = PatternCache.hash_input("test")
      PatternCache.put_result(hash, "detector", {:safe, %{}}, 1)
      Process.sleep(10)

      # Should be cached
      assert {:ok, _} = PatternCache.get_result(hash, "detector")

      # Wait for expiration and cleanup
      Process.sleep(1200)

      # Should be cleaned up
      assert :error = PatternCache.get_result(hash, "detector")
    end
  end

  describe "integration scenarios" do
    test "realistic usage pattern" do
      # Cache some patterns
      for i <- 1..10 do
        pattern = Regex.compile!("pattern#{i}")
        PatternCache.put_pattern("pattern#{i}", pattern)
      end

      # Cache some results
      for i <- 1..20 do
        hash = PatternCache.hash_input("input#{i}")
        result = if rem(i, 2) == 0, do: {:safe, %{}}, else: {:detected, %{confidence: 0.9}}
        PatternCache.put_result(hash, "detector", result, 300)
      end

      Process.sleep(50)

      # Verify patterns
      for i <- 1..10 do
        assert {:ok, _pattern} = PatternCache.get_pattern("pattern#{i}")
      end

      # Verify results
      for i <- 1..20 do
        hash = PatternCache.hash_input("input#{i}")
        assert {:ok, _result} = PatternCache.get_result(hash, "detector")
      end

      # Check stats
      stats = PatternCache.stats()
      assert stats.pattern_count == 10
      assert stats.result_count == 20
      assert stats.hit_rate > 0.0
    end
  end
end
