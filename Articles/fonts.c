#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <ft2build.h>
#include <math.h>
#include FT_FREETYPE_H
#include FT_GLYPH_H

__AFL_FUZZ_INIT();


int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {

if (size < 10) return 0; // Reject very small inputs

FT_Library library; // handle to library 
FT_Face face; // handle to face object 
FT_Error error; // hande to error

// Init library
error = FT_Init_FreeType(&library);
if (error) { printf("Could not load the library"); return 0; }

    error = FT_New_Memory_Face(library,
                            data,    /* first byte in memory */
                            size,      /* size in bytes        */
                            0,         /* face_index           */
                            &face );
    if (error) { printf("Could not create a face"); return 0; }
    
    // Macros testing
    FT_HAS_HORIZONTAL(face);
    FT_HAS_VERTICAL(face);
    FT_HAS_KERNING(face);
    FT_HAS_FIXED_SIZES(face);
    FT_HAS_GLYPH_NAMES(face);
    FT_HAS_COLOR(face);
    FT_HAS_MULTIPLE_MASTERS(face);
    FT_HAS_SVG(face);
    FT_HAS_SBIX(face);
    FT_HAS_SBIX_OVERLAY(face);
    FT_IS_SFNT(face);
    FT_IS_SCALABLE(face);
    FT_IS_FIXED_WIDTH(face);
    FT_IS_CID_KEYED(face);
    FT_IS_TRICKY(face);
    FT_IS_NAMED_INSTANCE(face);
    FT_IS_VARIATION(face);

    // Cleanup
    FT_Done_Face(face);
    }

// Cleanup
FT_Done_FreeType(library);
return 0;
}
