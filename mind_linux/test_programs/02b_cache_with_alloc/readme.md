# How to run test program
- Prepare traces:
  ``` make generate_trace```
- Simple test in a multiple node:
  - Inside the first node, run `make run_uni_node1` for unipage test, `make run_multi_node1` for multipage test
  - Inside the second node, run `make run_uni_node2` for unipage test, `make run_multi_node2` for multipage test
