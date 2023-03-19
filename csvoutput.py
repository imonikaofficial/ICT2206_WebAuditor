import csv
import os


def csv_output(row):
    header_row = ['Control Check', 'Current Setting', 'Audit Finding', 'Remediation']
    if not os.path.exists('output.csv'):
        # If the file does not exist, create a new file with the header row
        with open('output.csv', mode='w', newline='') as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(header_row)
            writer.writerow(row)
    else:
        # If the file exists, check if it has a header row
        with open('output.csv', mode='r') as csv_file:
            reader = csv.reader(csv_file)
            header_row = next(reader, [])
            if header_row != header_row:
                # If the file does not have a header row, add it
                with open('output.csv', mode='w', newline='') as csv_file:
                    writer = csv.writer(csv_file)
                    writer.writerow(header_row)
                    writer.writerow(row)
            else:
                # If the file has a header row, find the next empty row to write the new data
                with open('output.csv', mode='a', newline='') as csv_file:
                    writer = csv.writer(csv_file)
                    found_empty_row = False
                    while not found_empty_row:
                        try:
                            next_row = next(reader)
                            if not any(next_row):
                                writer.writerow(row)
                                found_empty_row = True
                        except StopIteration:
                            writer.writerow(row)
                            found_empty_row = True