#include <ft2build.h>
#include FT_FREETYPE_H
#include FT_GLYPH_H
#include <math.h>

int main(int argc, char *argv[])
{
FT_Library library; // handle to library 
FT_Face face; // handle to face object 
FT_Error error; // hande to error
FT_UInt glyph_index; // Glyph index
FT_ULong charcode; // Char code
FT_Matrix matrix; // Matrix
FT_Vector delta; // Delta
FT_GlyphSlot  slot = face->glyph; // a small shortcut


error = FT_Init_FreeType(&library);
if (error) { printf("Could not load the library"); }

char *filename = argv[1];

// Create a face object
error = FT_New_Face(library, filename, 0, &face); 
if (error) { printf("Could not create a face"); return 0; }

// Setting the current char pixel size
error = FT_Set_Char_Size(face, 0, 16*64, 300,300);
if (error) { printf("Could not set current pixel size"); return 0; }

// Setting the pixel size
error = FT_Set_Pixel_Sizes(face, 0, 16);
if (error) { printf("Could not set current pixel size"); return 0; }

// Convert a Unicode character code to a font glyph index
glyph_index = FT_Get_Char_Index( face, charcode );

// Loading glyph from the face
error = FT_Load_Glyph(face, glyph_index, FT_LOAD_DEFAULT);
if (error) { printf("Could not load glyph from the face"); return 0; }

// Convert to bitmap
error = FT_Render_Glyph(face->glyph, FT_RENDER_MODE_NORMAL);
if (error) { printf("Could not convert glyph to bitmap"); return 0; }

// Setup matrix
double angle = (25.0 / 360) * 3.14159 * 2; 
matrix.xx = (FT_Fixed)(cos(angle) * 0x10000L);
matrix.xy = (FT_Fixed)(-sin(angle) * 0x10000L);
matrix.yx = (FT_Fixed)(sin(angle) * 0x10000L);
matrix.yy = (FT_Fixed)(cos(angle) * 0x10000L);
delta.x = 300 * 64;
delta.y = (480 - 200) * 64;

// Set transform
FT_Set_Transform(face, &matrix, &delta);

// Cleanup
FT_Done_Face(face);
FT_Done_FreeType(library);
return 0;
}
