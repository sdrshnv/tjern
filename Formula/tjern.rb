class Tjern < Formula
  desc "A happy little journaling app"
  homepage "https://github.com/sudarshanvankudre/tjern"
  url "https://github.com/sudarshanvankudre/tjern/archive/refs/tags/v0.5.0.tar.gz"
  sha256 "c4836f91d9713ad6051b2843f9eef4b6eaa43130be625b92eb3c243283365489"
  license "GPL-3.0"

  depends_on "go" => :build

  def install
    system "go", "build", *std_go_args(ldflags: "-s -w")
  end

  test do
    system "true"
  end
end
