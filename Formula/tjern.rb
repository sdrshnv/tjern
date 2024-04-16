class Tjern < Formula
  desc "A happy little journaling app"
  homepage "https://github.com/sudarshanvankudre/tjern"
  url "https://github.com/sudarshanvankudre/tjern/archive/refs/tags/v0.3.1.tar.gz"
  sha256 "8836a4c4d5a5e182a93ebdcad6072ea115ac6462304955a1eb7a73a49574d7b8"
  license "GPL-3.0"

  depends_on "go" => :build

  def install
    system "go", "build", *std_go_args(ldflags: "-s -w")
  end

  test do
    system "true"
  end
end
