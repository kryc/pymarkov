# Pre-Made Models

The models in this directory are trained on the following datasets.

## rockyou

The [rockyou data breach](https://en.wikipedia.org/wiki/RockYou#Data_breach) in 2009 is the most commonly used password list and features in many cybersecurity toolkits, including Kali Linux. The reason for its notoriety is that the passwords were stored entirely unencrypted so represent a realistic training set for analysis.

# hibp

The passwords from the [haveibeenpwned](https://haveibeenpwned.com/) leaked password list. These are utf8 encoded passwords from known compromised sites and services.

### Flat list
The following are models based on the flat list of passwords in the hibp dataset.
- [hibp](hibp.markov) - Flat list of passwords with no weighting or denoising.
- [hibp-lite](hibp-lite.markov) - Flat list with denoise filter of 1.
- [hibp-mini](hibp-mini.markov) - Flat list with denoise filter of 1000.

### Weighted
The following are weighted based on the occurence of each password in the hibp dataset. For example, if a password was found in 1000 data leaks then its bigram weightings in the model are increased by that frequency. This creates a much more representative dataset for determining password strength.
- [hibp-weighted](hibp-weighted.markov) - Weighted model based on occurence of each password.
- [hibp-weighted-lite](hibp-weighted-lite.markov) - Weighted model with denoise filter of 1.
- [hibp-weighted-mini](hibp-weighted-mini.markov) - Weighted model with denoise filter of 1000.