#include <ft2build.h>
#include FT_FREETYPE_H
#include FT_GLYPH_H


int main(int argc, char *argv[])
{

FT_Library library; // handle to library 
FT_Face face; // handle to face object 
FT_Error error; // hande to error
FT_Glyph glyph, glyph2; // Glyph and Glyph2
FT_UInt glyph_index; // Glyph index
FT_Matrix matrix; // Matrix
FT_Vector delta, origin, kerning; // Delta, Origin and Kerning
FT_BBox bbox; // Bbox
FT_ULong charcode; // Char code
FT_UInt previous; // Previous and Next

// Init library
error = FT_Init_FreeType(&library);
if (error) { printf("Could not load the library"); return 0; }

char *filename = argv[1];

// Create a face object
error = FT_New_Face(library, filename, 0, &face); 
if (error) { printf("Could not create a face"); return 0; }

// Convert a Unicode character code to a font glyph index
glyph_index = FT_Get_Char_Index( face, charcode);

// Load the glyph
error = FT_Load_Glyph(face, glyph_index, FT_LOAD_DEFAULT);
if (error) { printf("Could not load the glyph"); return 0; }

// Get the glyph
error = FT_Get_Glyph( face->glyph, &glyph );
if (error) { printf("Could not get the glyph"); return 0; }

// Copy the glyph
error = FT_Glyph_Copy( glyph, &glyph2 );
if (error) { printf("Could not copy the glyph"); return 0; }

// Translate glyph
delta.x = -100 * 64; /* coordinates are in 26.6 pixel format */
delta.y =   50 * 64;
FT_Glyph_Transform(glyph, 0, &delta);

// Transform glyph2 (horizontal shear)
matrix.xx = 0x10000L;
matrix.xy = 0.12 * 0x10000L;
matrix.yx = 0;
matrix.yy = 0x10000L;
FT_Glyph_Transform(glyph2, &matrix, 0);

// Measuring the glyph image
FT_Glyph_Get_CBox(glyph, FT_GLYPH_BBOX_UNSCALED, &bbox);

// Converting glyph image to a bitmap
origin.x = 32; /* 1/2 pixel in 26.6 format */
origin.y = 0;
error = FT_Glyph_To_Bitmap(&glyph, FT_RENDER_MODE_NORMAL, &origin, 1);
if (error) { printf("Could not convert the glyph to bitmap"); return 0; }

// Retrieve kerning information
error = FT_Get_Kerning(face, previous, glyph_index, FT_KERNING_DEFAULT, &kerning);
if (error) { printf("Could not retrieve the kerning info"); return 0; }

return 0;
}
