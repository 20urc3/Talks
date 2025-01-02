#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <ft2build.h>
#include <math.h>
#include FT_FREETYPE_H
#include FT_GLYPH_H

/* this lets the source compile without afl-clang-fast/lto */
#ifndef __AFL_FUZZ_TESTCASE_LEN

ssize_t       fuzz_len;
unsigned char fuzz_buf[1024000];

  #define __AFL_FUZZ_TESTCASE_LEN fuzz_len
  #define __AFL_FUZZ_TESTCASE_BUF fuzz_buf
  #define __AFL_FUZZ_INIT() void sync(void);
  #define __AFL_LOOP(x) \
    ((fuzz_len = read(0, fuzz_buf, sizeof(fuzz_buf))) > 0 ? 1 : 0)
  #define __AFL_INIT() sync()

#endif

__AFL_FUZZ_INIT();


int main(int argc, char  ** argv)
{

size_t        len; // how much input did we read?
unsigned char *buf; // test case buffer pointer
FT_Library library; // handle to library 
FT_Face face; // handle to face object 
FT_Error error; // hande to error
FT_UInt previous, glyph_index;
FT_Vector kerning;
FT_Fixed akerning;

buf = __AFL_FUZZ_TESTCASE_BUF; 

// Init library
error = FT_Init_FreeType(&library);
if (error) { printf("Could not load the library"); return 0; }



while (__AFL_LOOP(UINT_MAX)) {
    len = __AFL_FUZZ_TESTCASE_LEN; 
    if (len < 8) { continue; } // Check len minimum size

    error = FT_New_Memory_Face(library,
                            buf,    /* first byte in memory */
                            len,      /* size in bytes        */
                            0,         /* face_index           */
                            &face );
    if (error) { printf("Could not create a face"); return 0; }
    glyph_index = FT_Get_Char_Index(face, 0);

    FT_Load_Glyph(face, 1, FT_LOAD_DEFAULT);
    FT_Render_Glyph(face->glyph, FT_RENDER_MODE_NORMAL);
    FT_Get_Kerning(face, previous, glyph_index, FT_KERNING_DEFAULT, &kerning);
    FT_Get_Track_Kerning(face, (FT_Fixed) 4, (FT_Int) 3, (FT_Fixed*) akerning);
    
    // Cleanup
    FT_Done_Face(face);
    }

// Cleanup
FT_Done_FreeType(library);
return 0;

}
