require "language/go"

class Tjern < Formula
  desc "An end-to-end encrypted terminal based application for journaling"
  homepage "https://github.com/sudarshanvankudre/tjern"
  url "https://github.com/sudarshanvankudre/tjern/archive/refs/tags/v0.2.0.tar.gz"
  sha256 "dc657dee4e2db0b928047403c50b0fcc6ba5c378a94c8894483e1f6757bd049f"
  license "GPL-3.0-only"
  head "https://github.com/sudarshanvankudre/tjern.git"

  depends_on "go" => :build

  def install
    ENV["GOPATH"] = buildpath
    system "go", "build", *std_go_args
    bin.install "tjern"
  end

  test do
    system "true"
  end
end 