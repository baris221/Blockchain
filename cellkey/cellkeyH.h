#ifndef CELL_KEY_H
#define CELL_KEY_H

typedef struct cellKey {
 	Key* data;
 	struct cellKey* next;
} CellKey;

CellKey* create_cell_key(Key* key);
void add_cell_key(CellKey** cellKey, Key* key);
CellKey* read_public_keys(char* filename);
void print_list_keys(CellKey* LCK);
void delete_cell_key(CellKey* c);
void delete_list_keys(CellKey* cellKeys);
int listKeyLength(CellKey *list);

#endif