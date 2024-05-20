class Tjern < Formula
  desc "A happy little journaling app"
  homepage "https://github.com/sdrshnv/tjern"
  url "https://github.com/sdrshnv/tjern/archive/refs/tags/v0.7.1.tar.gz"
  sha256 "4c0815a8da50c939afa5833cc371e64c636ae3d18872ac36996431ed5e30aec4"
  license "GPL-3.0"

  depends_on "go" => :build

  def install
    system "go", "build", *std_go_args(ldflags: "-s -w")
  end

  test do
    system "true"
  end
end
