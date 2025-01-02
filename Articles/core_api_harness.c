#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <ft2build.h>
#include <math.h>
#include FT_FREETYPE_H
#include FT_GLYPH_H

#define NUM_ENCODINGS (sizeof(supported_encodings) / sizeof(supported_encodings[0]))
#define MAX_GLYPHS 256
#define BUFFER_SIZE 1024

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 10) return 0;  // Reject very small inputs

    FT_Library library;
    FT_Face face;
    FT_Error error;
    FT_UInt glyph_index;
    FT_Vector kerning, delta;
    FT_Matrix matrix;
    char buffer[BUFFER_SIZE];

    // Supported encodings array
    FT_Encoding supported_encodings[] = {
        FT_ENCODING_NONE,
        FT_ENCODING_MS_SYMBOL,
        FT_ENCODING_UNICODE,
        FT_ENCODING_SJIS,
        FT_ENCODING_PRC,
        FT_ENCODING_BIG5,
        FT_ENCODING_WANSUNG,
        FT_ENCODING_JOHAB,
        FT_ENCODING_ADOBE_STANDARD,
        FT_ENCODING_ADOBE_EXPERT,
        FT_ENCODING_ADOBE_CUSTOM,
        FT_ENCODING_ADOBE_LATIN_1,
        FT_ENCODING_OLD_LATIN_2,
        FT_ENCODING_APPLE_ROMAN
    };

    // Initialize FreeType library
    error = FT_Init_FreeType(&library);
    if (error) return 0;

    // Create new face from memory
    error = FT_New_Memory_Face(library, data, size, 0, &face);
    if (error) {
        FT_Done_FreeType(library);
        return 0;
    }

    // Initialize transformation matrix
    double angle = (data[0] % 360) * 3.14159 / 180.0;  // Use first byte for rotation
    matrix.xx = (FT_Fixed)(cos(angle) * 0x10000L);
    matrix.xy = (FT_Fixed)(-sin(angle) * 0x10000L);
    matrix.yx = (FT_Fixed)(sin(angle) * 0x10000L);
    matrix.yy = (FT_Fixed)(cos(angle) * 0x10000L);

    // Initialize delta based on input data
    delta.x = ((int16_t)(data[1] << 8 | data[2])) * 64;
    delta.y = ((int16_t)(data[3] << 8 | data[4])) * 64;

    // Test face properties
    if (FT_HAS_HORIZONTAL(face)) {
        // Get font metrics
        FT_Size_RequestRec req;
        req.type = FT_SIZE_REQUEST_TYPE_NOMINAL;
        req.width = 0;
        req.height = (data[5] % 32 + 8) * 64;  // 8-40 pt size
        req.horiResolution = 96;
        req.vertResolution = 96;
        FT_Request_Size(face, &req);
    }

    // Select and test different character maps
    if (face->num_charmaps > 0) {
        FT_Select_Charmap(face, supported_encodings[data[6] % NUM_ENCODINGS]);
        
        // Get all available characters
        FT_ULong charcode;
        FT_UInt gindex;
        charcode = FT_Get_First_Char(face, &gindex);
        
        // Store up to MAX_GLYPHS characters for testing
        FT_ULong charcodes[MAX_GLYPHS];
        FT_UInt gindices[MAX_GLYPHS];
        int num_chars = 0;
        
        while (gindex != 0 && num_chars < MAX_GLYPHS) {
            charcodes[num_chars] = charcode;
            gindices[num_chars] = gindex;
            num_chars++;
            charcode = FT_Get_Next_Char(face, charcode, &gindex);
        }

        // Test kerning if available
        if (FT_HAS_KERNING(face) && num_chars > 1) {
            for (int i = 0; i < num_chars - 1 && i < 10; i++) {  // Limit iterations
                FT_Vector kern;
                FT_Get_Kerning(face, gindices[i], gindices[i+1], 
                              FT_KERNING_DEFAULT, &kern);
                
                // Test track kerning
                FT_Fixed track_kern;
                FT_Get_Track_Kerning(face, face->size->metrics.x_ppem * 64,
                                   -2, &track_kern);
            }
        }

        // Test glyph loading and rendering
        for (int i = 0; i < num_chars && i < 10; i++) {  // Limit iterations
            error = FT_Load_Char(face, charcodes[i], FT_LOAD_DEFAULT);
            if (!error) {
                FT_Render_Glyph(face->glyph, FT_RENDER_MODE_NORMAL);
                
                // If glyph names are available, test name functions
                if (FT_HAS_GLYPH_NAMES(face)) {
                    FT_Get_Glyph_Name(face, gindices[i], buffer, BUFFER_SIZE);
                    FT_Get_Name_Index(face, (FT_String*)buffer);
                }
                
                // Test subglyph information if available
                if (face->glyph->format == FT_GLYPH_FORMAT_COMPOSITE) {
                    FT_UInt index;
                    FT_Int p1, p2;
                    FT_UInt flags;
                    FT_Matrix submatrix;
                    
                    for (int j = 0; j < face->glyph->num_subglyphs; j++) {
                        FT_Get_SubGlyph_Info(face->glyph, j, &index, &flags,
                                           &p1, &p2, &submatrix);
                    }
                }
            }
        }
    }

    // Test other face properties
    if (FT_HAS_MULTIPLE_MASTERS(face)) {
        // Could add Multiple Master specific tests here
    }

    if (FT_HAS_COLOR(face)) {
        // Could add color-specific tests here
    }

    // Get PostScript name and FSType flags
    FT_Get_Postscript_Name(face);
    FT_Get_FSType_Flags(face);

    // Cleanup
    FT_Done_Face(face);
    FT_Done_FreeType(library);
    return 0;
}
