defmodule LlmGuardTest do
  use ExUnit.Case
  doctest LlmGuard

  test "greets the world" do
    assert LlmGuard.hello() == :world
  end
end
