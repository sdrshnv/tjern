class Tjern < Formula
  desc "A happy little journaling app"
  homepage "https://github.com/sudarshanvankudre/tjern"
  url "https://github.com/sudarshanvankudre/tjern/archive/refs/tags/v0.6.2.tar.gz"
  sha256 "e280d8e16bc510b3cda4ccafa0619ecfd44d565efa33af6a264a0c4de1270b6a"
  license "GPL-3.0"

  depends_on "go" => :build

  def install
    system "go", "build", *std_go_args(ldflags: "-s -w")
  end

  test do
    system "true"
  end
end
