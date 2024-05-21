class Tjern < Formula
  desc "A happy little journaling app"
  homepage "https://github.com/sdrshnv/tjern"
  url "https://github.com/sdrshnv/tjern/archive/refs/tags/v0.7.3.tar.gz"
  sha256 "e5edfea3d20d2e47d4505be3fa11c3dc9178c3bd2da2dcb44a65d3cfa0ab67f6"
  license "GPL-3.0"

  depends_on "go" => :build

  def install
    system "go", "build", *std_go_args(ldflags: "-s -w")
  end

  test do
    system "true"
  end
end
