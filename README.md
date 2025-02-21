# pymarkov

pymarkov is a simple implementation of a markov model [Markov model](https://en.wikipedia.org/wiki/Markov_model) for use in password strength analysis.

It allows you to train a stochastic model on known compromised passwords and use that to analyse the strength of passwords.

## Building a Model

For example, building a model on the rockyou dataset.

```bash
python3 ./markov.py build ./rockyou.txt models/rockyou.markov
```

## Generating a Report

pymarkov can output a report of all of the bigram weights in a csv file.

```bash
python3 ./markov.py build models/rockyou.markov rockyou.csv
```

## Analyse a Password

pymarkov can analyse input passwords and output a logarithmic strength score.

```bash
python3 ./markov.py strength models/rockyou.markov password correcthorsebatterystaple
```
```text
password: 28.80
correcthorsebatterystaple: 94.80
```