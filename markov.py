import argparse
import csv
import math
import pickle
import pprint
import random
import sys

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

def report(model: dict, filename: str) -> None:
    '''Print a weights report as csv file'''
    with open(filename, 'wt', encoding='utf8', errors='ignore') as file:
        writer = csv.writer(file, lineterminator='\n')
        for char, next_chars in model.items():
            for next_char, prob in next_chars.items():
                writer.writerow([char, next_char, prob])

def strength(model: dict, password: str) -> float:
    '''Return the strength of the password. This is -log2 of the product of the probabilities of each character'''
    strength = 1
    for i in range(len(password) - 1):
        char = password[i]
        next_char = password[i + 1]
        if char not in model or next_char not in model[char]:
            # Use a very very small number
            prob = 0.000000001
        else:
            prob = model[char][next_char]
        strength *= prob
    strength = -math.log(strength, 2)
    
    return strength

def strengths(model: dict, passwords: list) -> list:
    '''Return a list of the strengths of a list of passwords'''
    return [strength(model, password) for password in passwords]

def analyse(model: dict, password: str) -> list:
    '''Return a list of the probabilities of a password.'''
    probabilities = []
    for i in range(len(password) - 1):
        char = password[i]
        next_char = password[i + 1]
        if char not in model or next_char not in model[char]:
            # Use a very very small number
            prob = 0.00000000001
        else:
            prob = model[char][next_char]
        probabilities.append((f'{char}{next_char}', prob))
    return probabilities

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
        sub_parser.add_argument('--detail', action='store_true', help='Show detailed analysis')
        args = sub_parser.parse_args(sys.argv[2:])
        if args.detail and len(args.password) > 1:
            raise ValueError('Cannot show detailed analysis for multiple passwords')
        model = load_model(args.model_file)
        for password in args.password:
            passowrd_strength = strength(model, password)
            print(f'{password}: {passowrd_strength:.2f}')
            if args.detail:
                pprint.pprint(analyse(model, args.password))
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