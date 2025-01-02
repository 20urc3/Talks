#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <ft2build.h>
#include <math.h>
#include FT_FREETYPE_H
#include FT_GLYPH_H

  

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
if (size < 10) return 0; // Reject very small inputs

FT_Library library; // handle to library 
FT_Face face; // handle to face object 
FT_Error error; // hande to error
FT_Matrix matrix; // Matrix
FT_Vector delta; // Delta

 // Create a size request
FT_Size_RequestRec req;
req.type = FT_SIZE_REQUEST_TYPE_NOMINAL;  // Request nominal size
req.width = 0;                            // Width in 26.6 fractional points (0 means same as height)
req.height = 16 * 64;                     // Height in 26.6 fractional points (16pt)
req.horiResolution = 96;                  // Horizontal resolution in dpi
req.vertResolution = 96;                  // Vertical resolution in dpi

// Setup matrix
double angle = (25.0 / 360) * 3.14159 * 2; 
matrix.xx = (FT_Fixed)(cos(angle) * 0x10000L);
matrix.xy = (FT_Fixed)(-sin(angle) * 0x10000L);
matrix.yx = (FT_Fixed)(sin(angle) * 0x10000L);
matrix.yy = (FT_Fixed)(cos(angle) * 0x10000L);
delta.x = 300 * 64;
delta.y = (480 - 200) * 64;

// Init library
error = FT_Init_FreeType(&library);
if (error) { printf("Could not load the library"); return 0; }

    error = FT_New_Memory_Face(library,
                            data,    /* first byte in memory */
                            size,      /* size in bytes        */
                            0,         /* face_index           */
                            &face );
    if (error) { printf("Could not create a face"); return 0; }
    
    // Sizing and Scaling testing

    FT_Set_Char_Size(face, (FT_F26Dot6) 64, (FT_F26Dot6) 0, (FT_UInt) 0, (FT_UInt) 24); 
    FT_Set_Pixel_Sizes(face, (FT_UInt) 24, (FT_UInt) 12);
    FT_Request_Size(face, &req);
    FT_Select_Size(face, 0);
    FT_Set_Transform(face, &matrix, &delta);
    FT_Get_Transform(face, &matrix, &delta);

    // Cleanup
    FT_Done_Face(face);
    }

// Cleanup
FT_Done_FreeType(library);
return 0;

}
