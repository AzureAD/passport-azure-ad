# Branch Structure
* **master**: The latest official GA version
* **dev**: The dev working branch of master

If you would like to contribute code to this library, you should branch from **dev**, and make a pull request for your topic branch against **dev** branch.

# Releases
All the previous releases can be found [here](https://github.com/AzureAD/passport-azure-ad/releases).

# Filing Bugs
Please file issues you see in the [issue tracker](https://github.com/AzureAD/passport-azure-ad/issues). Include:

- The version you are using.
- The behavior you are seeing. If at all possible, please submit a reduced repro or test that demonstrates the issue.
- What you expect to see.

# Instructions for Contributing Code

## Contributing bug fixes

We are currently accepting contributions in the form of bug fixes. A bug must have an issue tracking it in the issue tracker. Your pull request should include a link to the bug that you are fixing. If you've submitted a PR for a bug, please post a comment in the bug to avoid duplication of effort.

## Contributing features
Features (things that add new or improved functionality) may be accepted, but will need to first be approved (tagged with "Enhancement") in the issue.

## Legal
You will need to complete a Contributor License Agreement (CLA). Briefly, this agreement testifies that you are granting us permission to use the submitted change according to the terms of the project's license, and that the work being submitted is under appropriate copyright.

Please submit a Contributor License Agreement (CLA) before submitting a pull request. You may visit https://cla.microsoft.com to sign digitally. You only need to do this once. Once we have received the signed CLA, we'll review the request.

## Housekeeping
Your pull request should:

* Include a description of what your change intends to do
* Be based on a reasonably recent pull in the correct branch
    * Please rebase and squash all commits into a single one
* Pass all tests
* Have clear commit messages
* Include new tests for bug fixes and new features
* To avoid line ending issues, set `autocrlf = input` and `whitespace = cr-at-eol` in your git configuration

## Running tests
To run tests, first go to the root folder of this library, then type the following in command line

    npm install


This will install all the dependency packages, then cd to the test directory, and type the following command
    
    npm test

The tests will run automatically, and the terminal window will show how many tests passed/failed. 
