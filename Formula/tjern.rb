class Tjern < Formula
  desc "A happy little journaling app"
  homepage "https://github.com/sudarshanvankudre/tjern"
  url "https://github.com/sudarshanvankudre/tjern/archive/refs/tags/v0.6.0.tar.gz"
  sha256 "6670acdb4a172122f7c29e29bddaea2ffcdf1995d835be6de7ca732ff4c30fad"
  license "GPL-3.0"

  depends_on "go" => :build

  def install
    system "go", "build", *std_go_args(ldflags: "-s -w")
  end

  test do
    system "true"
  end
end
