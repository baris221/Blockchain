#ifndef BLOCKCHAIN_H
#define BLOCKCHAIN_H

typedef struct block {
 	Key* author;
 	CellProtected* votes;
 	unsigned char* hash;
 	unsigned char* previous_hash;
 	int nonce;
} Block;

typedef struct block_tree_cell {
	Block* block;
	struct block_tree_cell* father;
 	struct block_tree_cell* firstChild;
 	struct block_tree_cell* nextBro;
 	int height;
} CellTree;

Block *creerBlock(Key *author, CellProtected *votes, unsigned char *hash, unsigned char *previous_hash, int nonce);
void write_block(char *filename, Block *block);
Block *lireBlock(char *filename);
char *block_to_str(Block *block);
unsigned char* hash_function_block(const char* str);
int count_zeros(unsigned char* str);
void compute_proof_of_work(Block *B, int d);
int verify_block(Block *B, int d);
void delete_block(Block *B);


CellTree *create_node(Block *b);
int update_height(CellTree *father, CellTree *child);
void add_child(CellTree *father, CellTree *child);
void print_tree(CellTree *tree);
void delete_node(CellTree *node);
void delete_tree(CellTree *tree);

CellTree *highest_child(CellTree* cell);
CellTree *last_node(CellTree *tree);
CellProtected *votesBrancheMax(CellTree *tree);
void submit_vote(Protected *p);
void create_block(CellTree **tree, Key *author, int d);
void add_block(int d, char *name);
CellTree *read_tree();
Key *compute_winner_BT(CellTree *tree, CellKey *candidates, CellKey *voters, int sizeC, int sizeV);

#endif