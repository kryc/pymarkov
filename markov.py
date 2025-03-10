import argparse
import csv
import math
import pickle
import random
import sys

strength_lookup = {
    00.0: (0, 'Very weak'),
    30.0: (1, 'Weak'),
    60.0: (2, 'Moderate'),
    75.0: (3, 'Strong'),
    90.0: (4, 'Very strong'),
}

def build_model(filename: str) -> dict:
    '''Build a Markov model from a file of newline-separated passwords'''
    model = {}
    # Read each word in the file and build the counts
    # of the next character
    with open(filename, 'rt', encoding='utf8', errors='ignore') as file:
        for line in file:
            line = line.strip()
            if not line:
                continue
            for i in range(len(line) - 1):
                char = line[i]
                # Ignore NUL characters
                if char == '\0':
                    continue
                next_char = line[i + 1]
                if char not in model:
                    model[char] = {}
                if next_char not in model[char]:
                    model[char][next_char] = 0
                model[char][next_char] += 1
    # Convert counts to probabilities weights
    for char, next_chars in model.items():
        total = sum(next_chars.values())
        for next_char in next_chars:
            next_chars[next_char] /= total
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
    parser.add_argument('operation', type=str, choices=('build', 'report', 'strength', 'generate',), help='Action to perform')
    args = parser.parse_args(sys.argv[1:2])

    if args.operation == 'build':
        # Create new arg parser for remainder of arguments
        sub_parser = argparse.ArgumentParser(description='Password Markov model build')
        sub_parser.add_argument('filename', type=str, help='Password file to read')
        sub_parser.add_argument('model_file', type=str, help='Model file to write')
        args = sub_parser.parse_args(sys.argv[2:])
        model = build_model(args.filename)
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