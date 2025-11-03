import csv
import sqlite3


def trim_filename(string):
    try:
        start_index = string.index("linux/") + len("linux/")
        return string[start_index:]
    except ValueError:
        return string


def import_allocations_to_db(csv_filename, db_name="codeql_data.db"):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    # Create the table if it doesn't exist
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS kmalloc_calls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            call_site TEXT,
            call_expr TEXT,
            struct_type TEXT,
            struct_def TEXT,
            struct_size INTEGER,
            flags TEXT,
            alloc_size INTEGER,
            sizeof_expr TEXT,
            is_flexible TEXT
        )
    """
    )

    with open(csv_filename, "r") as csvfile:
        reader = csv.reader(csvfile, delimiter=",", quotechar='"')
        next(reader)
        for row in reader:
            # Check if the row has the correct number of columns
            if len(row) == 9:
                try:
                    call_site = trim_filename(row[0])
                    call_expr = row[1]
                    struct_type = row[2]
                    struct_def = trim_filename(row[3])
                    struct_size = int(row[4])
                    flags = row[5]

                    # Handle 'unknown' for alloc_size
                    try:
                        alloc_size = int(row[6])
                    except ValueError:
                        alloc_size = None

                    sizeof_expr = row[7]
                    is_flexible = row[8]

                    cursor.execute(
                        """
                        INSERT INTO kmalloc_calls (call_site, call_expr, struct_type, struct_def, struct_size, flags, alloc_size, sizeof_expr, is_flexible) 
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                        (
                            call_site,
                            call_expr,
                            struct_type,
                            struct_def,
                            struct_size,
                            flags,
                            alloc_size,
                            sizeof_expr,
                            is_flexible,
                        ),
                    )

                except (ValueError, IndexError) as e:
                    print(f"Skipping invalid row: {row} - Error: {e}")
            else:
                print(f"Skipping invalid row: {row}")

    conn.commit()
    conn.close()


def import_functions_to_db(csv_file, db_name="codeql_data.db"):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    # Create table if it doesn't exist
    cursor.execute(
        """
    CREATE TABLE IF NOT EXISTS function_locations (
      function_name TEXT,
      file_path TEXT,
      start_line INTEGER,
      end_line INTEGER
    )
  """
    )

    with open(csv_file, "r") as file:
        reader = csv.reader(file)
        next(reader)
        for row in reader:
            if len(row) == 4:

                cursor.execute(
                    """
        INSERT INTO function_locations (function_name, file_path, start_line, end_line)
        VALUES (?, ?, ?, ?)
      """,
                    (row[0], trim_filename(row[1]), row[2], row[3]),
                )
            else:
                print(f"Skipping invalid row: {row}")

    conn.commit()
    conn.close()


def import_configs_to_db(csv_file, db_name="codeql_data.db"):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    # Create table if it doesn't exist
    cursor.execute(
        """
    CREATE TABLE IF NOT EXISTS configs (
      function_name TEXT,
      config TEXT
    )
  """
    )

    with open(csv_file, "r") as file:
        reader = csv.reader(file)
        next(reader)
        for row in reader:
            if len(row) == 2:
                cursor.execute(
                    """
          INSERT INTO configs (function_name, config)
          VALUES (?, ?)
        """,
                    row,
                )
            else:
                print(f"Skipping invalid row: {row}")

    conn.commit()
    conn.close()


# Example usage:
import_allocations_to_db("allocations.csv")
import_functions_to_db("functions.csv")
import_configs_to_db("configs.csv")
