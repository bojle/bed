# bed - binary editor

bed arises from a very peculiar need of mine where i require certain operations
to be performed on binary data. these include: extracting a range of bytes,
splitting entire data given a byte pattern and more as i require. 

- `bed -h` returns the usage for bed
- running `make` builds it

bed is being used in a file format reverse engineering project that i've
undertaken. for example, the split feature in particular, is useful to separate
a file in chunks given a delimiter. this can help in isolating sections in a
file. 
