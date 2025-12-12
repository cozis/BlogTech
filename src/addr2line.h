#ifndef _WIN32
#ifndef ADDR2LINE_INCLUDED
#define ADDR2LINE_INCLUDED

#define ADDR2LINE_ITEM_LIMIT 32

typedef struct {
    string func;
    string file;
    int    line;
} Addr2LineItem;

typedef struct {
    char *ptr;
    int   count;
    Addr2LineItem items[ADDR2LINE_ITEM_LIMIT];
} Addr2LineResult;

int addr2line(string executable, u64 *ptrs, int num_ptrs,
    Addr2LineResult *result);

void addr2line_free_result(Addr2LineResult *result);

#endif // ADDR2LINE_INCLUDED
#endif // !_WIN32