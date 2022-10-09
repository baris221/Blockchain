#ifndef HASH_TABLE_H
#define HASH_TABLE_H

#include "../key/keyH.h"

typedef struct hashcell {
 	Key* key;
 	int val;
} HashCell;

typedef struct hashtable {
 	HashCell** tab;
 	int size;
} HashTable;

HashCell* create_hashcell(Key* key);
int hash_function(Key* key, int size);
int find_position(HashTable* t, Key* key);
HashTable* create_hashtable(CellKey* keys, int size);
void print_hashtable(HashTable* t);
void delete_hashtable(HashTable* t);
Key* compute_winner(CellProtected* decl, CellKey* candidates, CellKey* voters, int sizeC, int sizeV);

#endif