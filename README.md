### Preconditions for running the detector:
* Install angr: `pip install angr`
* Install monkeyhex: `pip install monkeyhex`
* Put `detector.py`, `shadow.py` - and if you want to test, also `run_some_tests.py`, `run_all_tests.py` and the `test` folder - within the same folder.

### Detector tested with:
* OS: `Microsoft Windows 11 Pro`
* Python version: `3.11.4`
* angr version: `9.2.184`
* g++ version: `g++.exe (MinGW.org GCC-6.3.0-1) 6.3.0`

### Run detector or tests
* Use detector in your own python script: Import the detector with `import detector` and use the function `detect()`. Look at the documentation right at the function definition for how to use it.
* How to run all tests: Simply run `run_all_tests.py`. It will give you verbose output.
* How to run specific tests: Run `run_some_tests.py` and use one of the many arguments that you can provide in order to customize which tests you exactly want to run. To understand which argument does what, just run `python run_some_tests.py -h`.

### How are the tests written and how are they to be interpreted

As you can see in the `test` folder, there are two main groups of tests, `MemoryManagement` and `MemoryUsage`. The tests in the former sub-folder test the detector's ability to recongize vulnerabilities caused by bad memory management (e.g. a call to `free` with the wrong pointer) while the tests in the latter sub-folder test the detector's ability to recongize vulnerabilities caused by bad memory usage (e.g. an attempt to access memory locations which are located outside of allocated buffers).

Each of those sub-folders contains two more sub-folders, called `Concrete` and `Symbolic`. Those contain test cases that use concrete values in the former sub-folder, and symbolic values in the latter one.

Each of these sub-folders contains two more sub-folders, called `Correct` and `Incorrect`. The folder `Correct` contains various test cases which test the decetor's ability to not recognize false positives, while the `Incorrect` folder contains test cases which test the detector's ability to not recognize false negatives.

The files `run_all_tests.py` and `run_some_tests.py` compile each of the files of the `test` folder, and subsequently run `detect` on those files. The (customizable) tests that they perform are the follwing ones:
* They test all modes that the detector supports.
* Does the detector correctly recognize the presence/absence of a vulnerability?
* If there is a vulnerability, does the detector recognize it in the correct place? For this each of the test cases in the `Incorrect` folder contains two function calls `to_reach` and `not_to_reach()`.
* Are the only simulation manager stashes which contain states the two stashes `vuln` and `deadended`?
* If there is a vulnerability, then extract the standard input from the first state in the `vuln` stash and run the compiled test binary with that standard input to prove that the vulnerability indeed exists. This is the reason why all the tests in the `Incorrect` folder use macros `MALLOC, FREE, CALLOC, REALLOC, READ, WRITE` instead of running the functions `malloc, free, calloc, realloc` or reading and writing by dereferencing using the `*` operator. Those macros call the mentioned functions / dereferencing operations, but also print the arguments and return values of them to show that the vulnerability has actually been found.

So, the files `run_all_tests.py` and `run_some_tests.py` do everything for the usery, except for the fact that the user must look at the output of the macros when the test binaries are run, and verify that there is indeed a vulnerability.