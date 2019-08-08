workflow "Build and test on pull request" {
  resolves = ["Print Zig Version", "Test With Zig Master"]
  on = "pull_request"
}

workflow "Build and test on push" {
  resolves = ["Print Zig Version", "Test With Zig Master"]
  on = "push"
}

action "Print Zig Version" {
	uses = "docker://euantorano/zig:master"
	args = "version"
}

action "Test With Zig Master" {
  uses = "docker://euantorano/zig:master"
  args = "build test"
}
