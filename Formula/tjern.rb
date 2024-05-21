class Tjern < Formula
  desc "A happy little journaling app"
  homepage "https://github.com/sdrshnv/tjern"
  url "https://github.com/sdrshnv/tjern/archive/refs/tags/v0.7.3.tar.gz"
  sha256 "12bf73754fd6ec488ce999a76aa95828d968ecd8e9b4d7ef1a1281e176711994"
  license "GPL-3.0"

  depends_on "go" => :build

  def install
    system "go", "build", *std_go_args(ldflags: "-s -w")
  end

  test do
    system "true"
  end
end
