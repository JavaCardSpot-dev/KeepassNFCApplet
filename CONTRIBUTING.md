# How to contribute
Hey, thanks for caring about this project!!

## Tests
Currently there are no tests, if you can contribute adding them it would be really useful.
In case, consider also checking the tests execution with the [Gradle](README.md#gradle) build system in the TravisCI [config file](.travis.yml).

When there will be tests present, consider adding tests to verify your adds, and check the correctness of any already present test.

## Submitting changes
If tests are OK, consider sending a [Pull Request](https://github.com/JavaCardSpot-dev/KeepassNFCApplet/pull/new/master) clearly stating the nature of your changes (read more about [pull requests](http://help.github.com/pull-requests/) from GitHub).
Please follow our coding conventions (below) and make sure all of your commits are atomic (one feature per commit).

## Coding conventions
Start reading our code and you'll get the hang of it. Anyway:
  * Indentation is a tab
  * Opening and closing brackets have their own line in methods
  * Explicit casting WITHOUT space from the value, both variable name (`(short)var`) and hardcoded (`(short)2`)
  * Spaces between operators (`decrypted + 1`), arguments (`func(arg1, arg2)`) and around assignments (`var = newvalue`) are ALWAYS present.
  * NO IDE-specific configuration files
  * NO warning suppression comments/decorators
  * Consider keeping the code more readable when possible
