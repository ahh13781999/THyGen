import csv

def find_longest_csv_line(file_path):
    longest_line = ""
    max_length = 0

    with open(file_path, 'r', newline='', encoding='utf-8') as csvfile:  # Use 'utf-8' or another encoding
        csv_reader = csv.reader(csvfile)
        for row in csv_reader:
            row_str = ','.join(row)
            row_length = len(row_str)
            if row_length > max_length:
                max_length = row_length
                longest_line = row_str

    return longest_line, max_length

file_path = './dataset.csv'
longest_line, length = find_longest_csv_line(file_path)

print(f"The longest CSV line is: {longest_line}")
print(f"Length: {length} characters")