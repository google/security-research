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

def import_macroinvocations_to_db(csv_file, db_name="codeql_data.db"):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    # Create table if it doesn't exist
    cursor.execute(
        """
    CREATE TABLE IF NOT EXISTS macroinvocation_locations (
      macroinvocation_name TEXT,
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
        INSERT INTO macroinvocation_locations (macroinvocation_name, file_path, start_line, end_line)
        VALUES (?, ?, ?, ?)
      """,
                    (row[0], trim_filename(row[1]), row[2], row[3]),
                )
            else:
                print(f"Skipping invalid row: {row}")

    conn.commit()
    conn.close()


def import_macros_to_db(csv_file, db_name="codeql_data.db"):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    # Create table if it doesn't exist
    cursor.execute(
        """
    CREATE TABLE IF NOT EXISTS macro_locations (
      macro_name TEXT,
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
        INSERT INTO macro_locations (macro_name, file_path, start_line, end_line)
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
      config TEXT,
      path TEXT,
      ifdef INTEGER,
      endif INTEGER,
      else_ INTEGER
    )
  """
    )

    with open(csv_file, "r") as file:
        reader = csv.reader(file)
        next(reader)
        for row in reader:
            if len(row) == 5:
                cursor.execute(
                    """
          INSERT INTO configs (config, path, ifdef, endif, else_)
          VALUES (?, ?, ?, ?, ?)
        """,
        (row[0], trim_filename(row[1]), row[2], row[3], row[4]),
                )
            else:
                print(f"Skipping invalid row: {row}")

    conn.commit()
    conn.close()


def import_conditions_to_db(csv_file, db_name="codeql_data.db"):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    # Create table if it doesn't exist
    cursor.execute(
        """
    CREATE TABLE IF NOT EXISTS conditions (
      type TEXT,
      definition TEXT,
      condition TEXT,
      argument TEXT,
      call TEXT,
      call_location TEXT
    )
  """
    )

    with open(csv_file, "r") as file:
        reader = csv.reader(file)
        next(reader)
        for row in reader:
            if len(row) == 6:
                cursor.execute(
                    """
          INSERT INTO conditions (type, definition, condition, argument, call, call_location)
          VALUES (?, ?, ?, ?, ?, ?)
        """,
        (row[0], trim_filename(row[1]), trim_filename(row[2]), row[3], row[4], trim_filename(row[5])),
                )
            else:
                print(f"Skipping invalid row: {row}")

    conn.commit()
    conn.close()


def import_syscall_reachable_to_db(csv_file, db_name="codeql_data.db"):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    # Create table if it doesn't exist
    cursor.execute(
        """
    CREATE TABLE IF NOT EXISTS syscall_node (
      syscall TEXT,
      function TEXT,
      syscall_location TEXT,
      function_location TEXT
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
          INSERT INTO syscall_node (syscall, function, syscall_location, function_location)
          VALUES (?, ?, ?, ?)
        """,
        (row[0], row[1], trim_filename(row[2]), trim_filename(row[3])),
                )
            else:
                print(f"Skipping invalid row: {row}")

    conn.commit()
    conn.close()

def import_conditions_reachable_to_db(csv_file, db_name="codeql_data.db"):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    # Create table if it doesn't exist
    cursor.execute(
        """
    CREATE TABLE IF NOT EXISTS conditions_node (
      conditions TEXT,
      function TEXT,
      conditions_location TEXT,
      function_location TEXT
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
          INSERT INTO conditions_node (conditions, function, conditions_location, function_location)
          VALUES (?, ?, ?, ?)
        """,
        (row[0], row[1], trim_filename(row[2]), trim_filename(row[3])),
                )
            else:
                print(f"Skipping invalid row: {row}")

    conn.commit()
    conn.close()

def import_field_access_to_db(csv_file, db_name="codeql_data.db"):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    # Create table if it doesn't exist
    cursor.execute(
        """
    CREATE TABLE IF NOT EXISTS field_access (
      type TEXT,
      field TEXT,
      parent TEXT,
      location TEXT
    )
  """
    )

    with open(csv_file, "r") as file:
        reader = csv.reader(file)
        next(reader)
        for row in reader:
            if "unknown" in row or "unnamed" in row:
              continue
            if len(row) == 4:
                cursor.execute(
                    """
          INSERT INTO field_access (type, field, parent, location)
          VALUES (?, ?, ?, ?)
        """,
        (row[0], row[1], row[2], trim_filename(row[3])),
                )
            else:
                print(f"Skipping invalid row: {row}")

    conn.commit()
    conn.close()

def import_ops_targets_to_db(csv_file, db_name="codeql_data.db"):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    # Create table if it doesn't exist
    cursor.execute(
        """
    CREATE TABLE IF NOT EXISTS ops_targets (
      definition TEXT,
      parent TEXT,
      field TEXT,
      target TEXT,
      target_file TEXT,
      target_start INTEGER,
      target_end INTEGER,
      exprcall_file TEXT,
      exprcall_line INTEGER,
      exprcall_parent_start INTEGER,
      exprcall_parent_end INTEGER
    )
  """
    )

    with open(csv_file, "r") as file:
        reader = csv.reader(file)
        next(reader)
        for row in reader:
            if "unknown" in row or "unnamed" in row:
              continue
            if len(row) == 11:
                cursor.execute(
                    """
          INSERT INTO ops_targets (definition, parent, field, target, target_file, target_start, target_end, exprcall_file, exprcall_line, exprcall_parent_start, exprcall_parent_end)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (trim_filename(row[0]), row[1], row[2], row[3], trim_filename(row[4]), row[5], row[6], trim_filename(row[7]), row[8], row[9], row[10])),
            else:
                print(f"Skipping invalid row: {row}")

    conn.commit()
    conn.close()

# Example usage:
#import_allocations_to_db("allocations.csv")
#import_functions_to_db("functions.csv")
#import_configs_to_db("configs.csv")
#import_conditions_to_db("conditions.csv")
#import_syscall_reachable_to_db("syscall-leaf.csv")
#import_conditions_reachable_to_db("conditions-leaf.csv")
#import_macros_to_db("macros.csv")
#import_macroinvocations_to_db("macro_invocations.csv")
#import_field_access_to_db("field-access-type.csv")
import_ops_targets_to_db("ops_target_calls.csv")
