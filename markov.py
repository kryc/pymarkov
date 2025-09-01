import argparse
import csv
import hashlib
import itertools
import math
import multiprocessing
import pickle
import random
import re
import sys
import unicodedata

strength_lookup = {
    00.0: (0, 'Very weak'),
    30.0: (1, 'Weak'),
    60.0: (2, 'Moderate'),
    75.0: (3, 'Strong'),
    90.0: (4, 'Very strong'),
}

HEX_REGEX = re.compile(r'^\$HEX\[(?:[0-9A-Fa-f]{2})+\]$')

def _convert_counts_to_weights(model: dict) -> dict:
    '''Convert counts to weights in the model'''
    for _, next_chars in model.items():
        total = sum(next_chars.values())
        for next_char in next_chars:
            next_chars[next_char] /= total
    return model

def _add_word_to_model(model: dict, word: str, weight: int) -> None:
    '''Add a word to the model, updating the counts of next characters'''
    for i in range(len(word) - 1):
        char = word[i]
        next_char = word[i + 1]
        if char not in model:
            model[char] = {}
        if next_char not in model[char]:
            model[char][next_char] = 0
        model[char][next_char] += weight

def _is_printable_utf8(word: str) -> bool:
    '''Check if a string is printable UTF-8'''
    for codepoint in map(ord, word):
        if (
            codepoint <= 0x1F or codepoint == 0x7F or                      # ASCII control
            0x80 <= codepoint <= 0x9F or                                   # C1 control
            0xD800 <= codepoint <= 0xDFFF or                               # Surrogates
            codepoint in {0xFFFE, 0xFFFF} or                               # Noncharacters
            0xE000 <= codepoint <= 0xF8FF or                               # BMP Private Use
            0xF0000 <= codepoint <= 0xFFFFD or                             # SPUA-A
            0x100000 <= codepoint <= 0x10FFFD                              # SPUA-B
        ):
            return False
    return True

def build_model(filename: str) -> dict:
    '''Build a Markov model from a file of newline-separated passwords'''
    model = {}
    # Read each word in the file and build the counts
    # of the next character
    with open(filename, 'rt', encoding='utf8', errors='ignore') as file:
        for line in file:
            line = line.rstrip('\n')
            if not line:
                continue
            # Check if the word is printable UTF-8
            if not _is_printable_utf8(line):
                continue
            # Normalize the word to NFC
            line = unicodedata.normalize('NFC', line)
            _add_word_to_model(model, line, 1)
    # Convert counts to probabilities weights
    model = _convert_counts_to_weights(model)
    return model

def _hashing_worker(words: list) -> tuple:
    '''Worker function to hash a word and return its SHA1 digest and the word itself'''
    hashes = []
    skipped = 0
    for word in words:
        word = word.rstrip('\n')
        if not word:
            skipped += 1
            continue
        # Decode $HEX[...] encodings
        if re.match(HEX_REGEX, word):
            word_bytes = bytes.fromhex(word[5:-1])
            try:
                word = word_bytes.decode('utf8')
            except UnicodeDecodeError:
                skipped += 1
                continue
        # Skip non-printable UTF-8 words
        if not _is_printable_utf8(word):
            skipped += 1
            continue
        # Hash the string and return it
        hash_digest = hashlib.sha1(word.encode('utf8')).digest()
        hashes.append((hash_digest, word,))
    return hashes, skipped

def _build_wordlist_lookup_table(wordlist: str, threads: int) -> dict:
    '''Build a lookup table from a wordlist file'''
    lookup_table = {}
    skipped = 0
    with open(wordlist, 'rt', encoding='utf8', errors='ignore') as file:
        with multiprocessing.Pool(threads) as pool:
            for values, skipped_block in pool.imap_unordered(_hashing_worker, itertools.batched(file, 8192)):
                skipped += skipped_block
                for hash_digest, word in values:
                    lookup_table[hash_digest] = word
                print(f'Processed {len(lookup_table)} words, skipped {skipped} ({skipped/len(lookup_table)*100.0:.2f}%)', end='\r', file=sys.stderr)
    print('Skipped', skipped, 'invalid words from wordlist')
    return lookup_table

def build_model_hibp(pwnedpasswords: str, wordlist: str, threads: int) -> dict:
    '''Build a Markov model from the Have I Been Pwned pwnedpasswords list and a wordlist file'''
    # Step 1 we read the wordlist and hash all of the words with sha1
    print('Building lookup table from wordlist...')
    lookup_table = _build_wordlist_lookup_table(wordlist, threads)
    # Print first three entries
    print('Lookup table built with', len(lookup_table), 'entries')
    # Step 2 we read the pwnedpasswords file and build a model
    # The pwnedpasswords file is a list of sha1 hashes of passwords and their count
    # The format is <sha1 hash>:<count>
    model = {}
    print('Building model from pwnedpasswords...')
    number_missing = 0
    with open(pwnedpasswords, 'rt', encoding='utf8', errors='ignore') as file:
        for line in file:
            line = line.strip()
            if not line:
                continue
            hash_str, count_str = line.split(':')
            assert len(hash_str) == 40
            count = int(count_str)
            hash_bytes = bytes.fromhex(hash_str)
            # Check if the hash is in the lookup table
            if hash_bytes in lookup_table:
                password = lookup_table[hash_bytes]
                # The password is valid UTF8, but we can safely
                # normalize it to help keep the model size down
                password = unicodedata.normalize('NFC', password)
                # Build the model from the password
                _add_word_to_model(model, password, count)
            else:
                number_missing += 1
    print('Model built with', len(model), 'entries')
    print('Number of missing hashes:', number_missing)
    # Convert counts to probabilities weights
    model = _convert_counts_to_weights(model)
    return model

def save_model(model: dict, filename: str) -> None:
    '''Save the model to a file using pickle'''
    with open(filename, 'wb') as file:
        pickle.dump(model, file)

def load_model(filename: str) -> dict:
    '''Load the model from a file using pickle'''
    with open(filename, 'rb') as file:
        return pickle.load(file)

def augment_model(model: dict, filename: str, multiplier: int) -> dict:
    '''Augment the model with a local dictionary'''
    # Create a new weighting model from the file
    augmentation_model = build_model(filename)
    # Multiply the weights by the multiplier
    for char, next_chars in augmentation_model.items():
        for next_char, weight in next_chars.items():
            augmentation_model[char][next_char] *= multiplier
    # Merge the models
    for char, next_chars in augmentation_model.items():
        if char not in model:
            model[char] = {}
        for next_char, weight in next_chars.items():
            if next_char not in model[char]:
                model[char][next_char] = 0
            model[char][next_char] += weight
    return model

def report(model: dict, filename: str) -> None:
    '''Print a weights report as csv file'''
    with open(filename, 'wt', encoding='utf8', errors='ignore') as file:
        writer = csv.writer(file, lineterminator='\n')
        for char, next_chars in model.items():
            for next_char, prob in next_chars.items():
                writer.writerow([char, next_char, prob])

def shortest_repeating_substring(password: str) -> str:
    '''Find the shortest repeating substring in the given string'''
    result = None
    for length in range(len(password) // 2, 0, -1):
        if len(password) % length == 0:
            substring = password[:length]
            if substring * (len(password) // length) == password:
                result = password[:length]
    return result or password

def flatten_repeating_substrings(password: str) -> str:
    '''Flatten repeated whole substrings in the given string with a minimum length of two characters'''
    result = []
    i = 0
    while i < len(password):
        for length in range(2, len(password) - i + 1):  # Start length from 2
            substring = password[i:i + length]
            repeat_count = 1
            while i + repeat_count * length < len(password) and password[i:i + length] == password[i + repeat_count * length:i + (repeat_count + 1) * length]:
                repeat_count += 1
            if repeat_count > 1:
                result.append(substring)
                i += repeat_count * length
                break
        else:
            result.append(password[i])
            i += 1
    return ''.join(result)

def _strength(model: dict, password: str, length_adjust: bool = False, fold: bool = True) -> float:
    '''Return the strength of the password. This is -log2 of the product of the probabilities of each character'''
    # Check for repeating substrings
    password = flatten_repeating_substrings(password) if fold else password
    # Normalize the password to NFC
    password = unicodedata.normalize('NFC', password)
    # Calculate the product of the probabilities of each character
    probabilities = []
    strength_val = 1
    for i in range(len(password) - 1):
        char = password[i]
        next_char = password[i + 1]
        if char not in model or next_char not in model[char]:
            # Use a very very small number
            prob = 0.000000001
        else:
            prob = model[char][next_char]
        strength_val = strength_val * prob * pow(1.1, i+1) if length_adjust else strength_val * prob
        probabilities.append((f'{char}{next_char}', prob))
    strength_val = -math.log(strength_val, 2)
    return strength_val, probabilities

def strength(model: dict, password: str, length_adjust: bool = False, fold: bool = True) -> float:
    '''Return the strength of the password. This is -log2 of the product of the probabilities of each character'''
    strength_val, _ = _strength(model, password, length_adjust, fold)
    return strength_val

def analyse(model: dict, password: str, length_adjust: bool = False, fold: bool = True) -> list:
    '''Return a list of the probabilities of a password.'''
    _, probabilities = _strength(model, password, length_adjust, fold)
    return probabilities

def score(strength: float) -> tuple:
    '''Return the strength lookup value for a given strength'''
    result = strength_lookup[0.0]
    for lookup_strength, lookup_value in strength_lookup.items():
        if strength >= lookup_strength:
            result = lookup_value
    return result

def strengths(model: dict, passwords: list) -> list:
    '''Return a list of the strengths of a list of passwords'''
    return [strength(model, password) for password in passwords]

def generate_text(model: dict, length: int, start: str) -> str:
    '''Generate text of a given length using the Markov model'''
    if start and start[0] not in model:
        raise ValueError(f"Start character '{start[0]}' not in model")
    current_char = start[0] if start else random.choice(list(model.keys()))
    output = current_char
    for _ in range(length - 1):
        next_chars = list(model.get(current_char, {}).keys())
        if not next_chars:
            break
        next_char = random.choices(next_chars, weights=[model[current_char][nc] for nc in next_chars])[0]
        output += next_char
        current_char = next_char
    return output

def main():
    '''Main function'''
    parser = argparse.ArgumentParser(description='Password Markov model analysis')
    parser.add_argument('operation', type=str, choices=('build', 'buildhibp', 'report', 'strength', 'generate',), help='Action to perform')
    args = parser.parse_args(sys.argv[1:2])

    if args.operation == 'build':
        # Create new arg parser for remainder of arguments
        sub_parser = argparse.ArgumentParser(description='Password Markov model build')
        sub_parser.add_argument('filename', type=str, help='Password file to read')
        sub_parser.add_argument('model_file', type=str, help='Model file to write')
        args = sub_parser.parse_args(sys.argv[2:])
        model = build_model(args.filename)
        save_model(model, args.model_file)
    elif args.operation == 'buildhibp':
        # Create new arg parser for remainder of arguments
        sub_parser = argparse.ArgumentParser(description='Password Markov model build from Have I Been Pwned pwnedpasswords list')
        sub_parser.add_argument('pwnedpasswords', type=str, help='Pwned passwords file to read')
        sub_parser.add_argument('wordlist', type=str, help='Wordlist file to perform lookups')
        sub_parser.add_argument('model_file', type=str, help='Model file to write')
        sub_parser.add_argument('--threads', type=int, help='Number of threads to use')
        args = sub_parser.parse_args(sys.argv[2:])
        model = build_model_hibp(args.pwnedpasswords, args.wordlist, args.threads)
        save_model(model, args.model_file)
    elif args.operation == 'report':
        # Create new arg parser for remainder of arguments
        sub_parser = argparse.ArgumentParser(description='Password Markov model report')
        sub_parser.add_argument('model_file', type=str, help='Model file to read')
        sub_parser.add_argument('report_file', type=str, help='Report file to write')
        args = sub_parser.parse_args(sys.argv[2:])
        model = load_model(args.model_file)
        report(model, args.report_file)
    elif args.operation == 'strength':
        # Create new arg parser for remainder of arguments
        sub_parser = argparse.ArgumentParser(description='Password Markov model analyze')
        sub_parser.add_argument('model_file', type=str, help='Model file to read')
        sub_parser.add_argument('password', nargs='+', type=str, help='Password to analyze')
        sub_parser.add_argument('--length-adjust', action='store_true', help='Adjust strength by length')
        sub_parser.add_argument('--no-fold', action='store_true', help='Do not fold repeating substrings')
        sub_parser.add_argument('--detail', action='store_true', help='Show detailed analysis')
        sub_parser.add_argument('--augment', type=str, help='Augment the strength meter with local dictionary')
        sub_parser.add_argument('--augment-multiplier', type=float, default=0.1, help='Multiplier weighting to apply to augmented dictionary')
        args = sub_parser.parse_args(sys.argv[2:])
        model = load_model(args.model_file)
        if args.augment:
            model = augment_model(model, args.augment, args.augment_multiplier)
        for password in args.password:
            password_strength = strength(model, password, args.length_adjust, not args.no_fold)
            scoreval, description = score(password_strength)
            print(f'{password}: {password_strength:.5f}, {scoreval} ({description})')
            if args.detail:
                for bigram, probability in analyse(model, password):
                    print(f'  {bigram} {probability:.5f}')
    elif args.operation == 'generate':
        # Create new arg parser for remainder of arguments
        sub_parser = argparse.ArgumentParser(description='Password Markov model generate')
        sub_parser.add_argument('model_file', type=str, help='Model file to read')
        sub_parser.add_argument('length', type=int, help='Length of password to generate')
        sub_parser.add_argument('--start', type=str, default='', help='Starting characters')
        args = sub_parser.parse_args(sys.argv[2:])
        model = load_model(args.model_file)
        print(generate_text(model, args.length, args.start))

if __name__ == '__main__':
    main()