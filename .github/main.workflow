workflow "Build and test on pull request" {
  resolves = ["Test With Zig Stable", "Test With Zig Master"]
  on = "pull_request"
}

workflow "Build and test on push" {
  resolves = ["Test With Zig Stable", "Test With Zig Master"]
  on = "push"
}

action "Test With Zig Stable" {
  uses = "docker://euantorano/zig:latest"
  args = "build test"
}

action "Test With Zig Master" {
  uses = "docker://euantorano/zig:master"
  args = "build test"
}
