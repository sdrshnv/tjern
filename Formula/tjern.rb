class Tjern < Formula
  desc "A happy little journaling app"
  homepage "https://github.com/sudarshanvankudre/tjern"
  url "https://github.com/sudarshanvankudre/tjern/archive/refs/tags/v0.3.0.tar.gz"
  sha256 "8b9cf04f1fb3c0639076118caf4a3e0c81f4aa2ff468f10f14ec85a5d7def280"
  license "GPL-3.0"

  depends_on "go" => :build

  def install
    system "go", "build", *std_go_args(ldflags: "-s -w")
  end

  test do
    system "true"
  end
end
