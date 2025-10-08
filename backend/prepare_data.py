import pandas as pd
import os

# --- Configuration ---
INPUT_FILENAME = 'top-1m.csv'
OUTPUT_FOLDER = 'data'
OUTPUT_FILENAME = 'benign-urls.csv'
ROWS_TO_EXTRACT = 20000
# ---------------------

# Create the output folder if it doesn't exist
if not os.path.exists(OUTPUT_FOLDER):
    os.makedirs(OUTPUT_FOLDER)

output_path = os.path.join(OUTPUT_FOLDER, OUTPUT_FILENAME)

try:
    print(f"[*] Reading the first {ROWS_TO_EXTRACT} rows from '{INPUT_FILENAME}'...")
    
    # Read only the specified number of rows from the large CSV.
    # header=None tells pandas that our file doesn't have a title row.
    df = pd.read_csv(INPUT_FILENAME, header=None, nrows=ROWS_TO_EXTRACT)
    
    # The domain names are in the second column (index 1).
    domains_column = df[1]
    
    print(f"[*] Writing the extracted domains to '{output_path}'...")
    
    # Save the extracted column to a new CSV file.
    # index=False and header=False ensures we only get the list of domains.
    domains_column.to_csv(output_path, index=False, header=False)
    
    print(f"\n[+] Success! The file '{output_path}' was created with {ROWS_TO_EXTRACT} domains.")

except FileNotFoundError:
    print(f"\n[!] Error: The input file '{INPUT_FILENAME}' was not found.")
    print(f"    Please make sure it's inside the 'backend' folder before running this script.")
except Exception as e:
    print(f"\n[!] An unexpected error occurred: {e}")