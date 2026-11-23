query = input("SQL: ")
cursor.executemany(operation=query, seq_of_parameters=[])
