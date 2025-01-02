# Intro
Every fuzzing enthusiast dream is a program that takes a file as arguments, have a deep coverage and a fast speed execution. Unfortunately in the real world only few targets correspond to this description, allowing to dumb fuzz them (and you should not! See [this](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.persistent_mode.md). Most target are not fuzzable as such and requires you, the research, to do some heavy lifting before it is possible to efficiently fuzzing it.

In this article we are going to cover *how to fuzz a library*. From **getting started** to **persistent mode**. We will focus on [Freetype](http://freetype.org/) a software library that is used by all kinds of applications to access the contents of font files.

Fuzzing a library is summarize in those crucial steps:
- Instrumenting the library.
- Going through the documentation.
- Listing interesting functions.
- Write a harness.
- Write specifics harness.
- Gather a corpus.
- Running the fuzzing campaign.
- Triage results.

# Instrumenting the library

Instrumentation refers to the process of modifying a program's binary or source code to insert additional tracking and monitoring code that helps the fuzzer collect meaningful coverage information and guide the fuzzing process. This instrumentation allows AFL++ to understand which code paths are being executed during fuzzing, enabling more intelligent and efficient exploration of the program's potential execution paths.

If you instrument with **LTO mode** (**afl-clang-fast/afl-clang-lto**), the following options are available:
 -  Splitting integer, string, float, and switch comparisons so AFL++ can easier solve these. You can read more about this in [instrumentation/README.laf-intel.md](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.laf-intel.md).
 - A different technique (and usually a better one than laf-intel) is to instrument the target so that any compare values in the target are sent to AFL++ which then tries to put these values into the fuzzing data at different locations.  You can read more about this in [instrumentation/README.cmplog.md](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.cmplog.md).

## Installing AFL++

The installation instructions can be found [here](https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/INSTALL.md). First start by installing LLVM
```bash
# Install a specific version of LLVM:
wget https://apt.llvm.org/llvm.sh
chmod +x llvm.sh
sudo ./llvm.sh  # <version number>
```

Then you can proceed to install AFL++
```bash
sudo apt-get install -y build-essential python3-dev automake cmake git flex bison libglib2.0-dev libpixman-1-dev python3-setuptools cargo libgtk-3-dev
sudo apt-get install -y gcc-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-plugin-dev libstdc++-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-dev
sudo apt-get install -y ninja-build # for QEMU mode
sudo apt-get install -y cpio libcapstone-dev # for Nyx mode
sudo apt-get install -y wget curl # for Frida mode
sudo apt-get install -y python3-pip # for Unicorn mode
git clone https://github.com/AFLplusplus/AFLplusplus
cd AFLplusplus
make 
sudo make install
```

## Compiling a target library

The process of compiling a library can be more or less complex depending on the target. In this exercise Freetype compilation is a straightforward process.

```bash
git clone https://gitlab.freedesktop.org/freetype/freetype.git
cd freetype
./autogen.sh # Generates the configure file
./configure CC=afl-clang-lto CXX=afl-clang-lto++ CFLAGS="-O1" CXXFLAGS="-O1" 
make
```

If everything works correctly you will end up with multiple `.a` files composing the actual library.

## Testing the library

In order to verify everything went correctly, let's write a small harness. First we check the [Freetype documentation](http://freetype.org/freetype2/docs/documentation.html) page and find a [tutorial](http://freetype.org/freetype2/docs/tutorial/step1.html#section-1) which describes the basic steps to use the library. Following this guide we are going to write this very minimalist harness.

```c
#include <ft2build.h>
#include FT_FREETYPE_H
#include FT_GLYPH_H

int main(int argc, char ** argv)
{
FT_Library library; /* handle to library */
FT_Face face; /* handle to face object */
FT_Error error; /* hande to error*/


error = FT_Init_FreeType(&library);
if (error) { printf("Could not load the library."); }

char * filename = argv[1];
error = FT_New_Face(library, filename, 0, &face); /* create face object */
if (error) { printf("Could not create a face."); return 1; }

// Cleanup
FT_Done_Face(face);
FT_Done_FreeType(library);
return 0;
}
```

We can now compile our target with the following command:
```bash
afl-clang-lto simple_harness.c -I/path/to/include -L/path/to/freetype -lfreetype -o test
```

If everything goes well, you will end up with `test` `.elf` file that you can fuzz. You can try to fuzz it by running: `afl-fuzz -i inputs -o output -- ./test @@`

![[Pasted image 20241119071640.png]]

Congratulations, you just harnessed a library ! Well, this program does not so much isn't it ? In fact, what we wrote is very unlikely to yield new bugs. Freetype is a library that has been tested in the past and a function that performs so little actions is very unlikely to contains a memory issue (unless.. ?). It's time now to write a more advanced harness that has a chance to discover new bugs!
# Going through the documentation

Going through a library or a software documentation can be a tedious task. It's very often overlooked because after all: a few days of debugging can avoid you the pain of reading a few pages of doc right ?  Joke aside, willing to fuzz a certain library or program means wanting to learn about it. The strategy of throwing dumb fuzzer to any target you can think of, without spending the time and efforts to learn about the target revealed itself very inefficient nowadays. When writing an harness for a library it is important to understand *what* the library is doing, what are the main purposes ? What are the main features ? How it processes inputs ? What are the internal mechanisms of the library ? What are the features that processes user's inputs?

We will take this time to gain a first understanding of the library, it's main components and capabilities and what part is worth trying to fuzz. In the main [documentation](https://freetype.org/freetype2/docs/documentation.html) of Freetype we find the[FAQ](https://freetype.org/freetype2/docs/ft2faq.html) section that contains a link to he page [what is Freetype](https://freetype.org/freetype2/docs/ft2faq.html#general-what).

#### What is FreeType ?
Freetype is:
*"It is a software library that can be used by all kinds of applications to access the contents of font files. Most notably, it supports the following features.*

- *It provides a uniform interface to access font files. It supports both bitmap and scalable formats, including TrueType, OpenType, Type1, CID, CFF, Windows FON/FNT, X11 PCF, and others.*
- *It supports high-speed, anti-aliased glyph bitmap generation with 256 gray levels.*
- *It is extremely modular, each font format being supported by a specific module. A build of the library can be tailored to support only the formats you need, thus reducing code size. A minimal anti-aliasing build of FreeType can be less than 30kByte."*

The documentation also describes what FreeType is **not**:

*FreeType doesn't try to perform a number of sophisticated things, because it focuses on being an excellent font service.This means that the following features are not supported directly by the library.*

- ***rendering glyphs to arbitrary surfaces***  
- ***glyph caching***  
- ***text layout***  

This gives us a basic idea of what FreeType does. Let's dig a bit deeper in the documentation and read the [Design](https://freetype.org/freetype2/docs/design/design-2.html) section.

#### FreeType Design

The documentation described FreeType as a *collection of components* where each of them is in charge of one specific task.

- *Client applications typically call the FreeType 2 **high-level API**, whose functions are implemented in a single component called the Base Layer.*    
- *Depending on the context or the task, the base layer then calls one or more module components to perform the work. In most cases, the client application doesn't need to know which module was called.*   
- *The base layer also contains a set of routines that are used for generic things like memory allocation, list processing, I/O stream parsing, fixed-point computation, etc. These functions can also be called by a module at any time, and they form what is called the **low-level base API**.*
![[Pasted image 20241119074529.png]]


#### Internal objects and classes

In this [section] (https://freetype.org/freetype2/docs/design/design-4.html) is described the memory management and input stream basic mechanisms of FreeType. Here below of few interesting information extracted from the documentation.

- Most memory management operations are performed through three specific routines of the base layer: FT_Alloc, FT_Realloc, and FT_Free. Each one of these functions expects a FT_Memory handle as its first parameter. Note, however, that there exist more, similar variants for specific purposes which we skip here for simplicity. By default, this manager uses the ANSI functions malloc, realloc, and free. However, as ftsystem is a replaceable part of the base layer, a specific build of the library could provide a different default memory manager.
- Font files are always read through FT_Stream objects. The definition of [`FT_StreamRec`](https://freetype.org/freetype2/docs/reference/ft2-system_interface.html#ft_streamrec) is located in the public header file ftsystem.h, which allows client developers to provide their own implementation of streams if they wish so. The function [`FT_New_Face`](https://freetype.org/freetype2/docs/reference/ft2-base_interface.html#ft_new_face) always automatically creates a new stream object from the C pathname given as its second argument. This is achieved by calling the (internal) function FT_Stream_Open provided by the ftsystem component. As the latter is replaceable, the implementation of streams may vary greatly between platforms. As an example, the default implementation of streams is located in the file src/base/ftsystem.c and uses the ANSI functions fopen, fseek, and fread. However, the Unix build of **FreeType 2 provides an alternative implementation that uses memory-mapped files, when available on the host platform, resulting in a significant access speed-up.**

![[Pasted image 20241119075311.png]]

#### Summary

In summary we learned that FreeType:
- Allows to access font type.
- Is composed of modules.
- Relies on the low-level API for i/o management.
- Most memory management are performed through specific routines.
- Font files are read through `FT_Stream` objects.
- The Unix build provides an implementation allowing to use memory-mapped file.

The documentation reveals several areas that deserve particular attention when working with or testing the library:

- The memory management system's centralized nature makes it a critical point for reliability testing
- The stream abstraction layer, especially in Unix builds with memory-mapped files, represents a complex interaction point
- The modular architecture suggests that testing should consider both module-specific and inter-module interactions

Thankfully, it is not mandatory to become an FreeType expert to be able to write good harnesses, we have now a solid understanding of its mechanisms and will be able to implement functions of the library in our harnesses.

# List interesting functions

Now that we gained a good understanding of what the library does, it's time to make a list of the functions that are worth to try fuzz testing or important for writing our harness. Beginning by the FreeType [tutorial](https://freetype.org/freetype2/docs/tutorial/index.html) page we collect these function
##### Tutorial 1
- Library init
	- Library initialization: `FT_Init_FreeType(&library)` 
- Loading face
	- Loading a Font Face from file: `FT_New_Face(library, "/usr/share/fonts/truetype/arial.ttf", 0, &face)` 
	- Loading a Font Face from memory: `FT_New_Memory_Face(library, buffer, size, 0, &face)`
	- From other sources: `FT_Open_Face(library, args, face_index, *aface)`
- Setting current pixel size
	- Set the char size: `FT_Set_Char_Size(face, 0, 16*64, 300, 300)`
	- Set the pixel size: `FT_Set_Pixel_Sizes(face, 0, 16 )
- Loading a glyph image
	- Covert Unicode character into glyph index: `glyph_index = FT_Get_Char_Index(face, charcode)`
	- Loading a glyph from the face: `FT_Load_Glyph(face, glyph_index,  load_flags)`
	- Convert glyph to bitmap: `FT_Render_Glyph(face->glyph, render_mode)`
	- Using other charmap: `FT_Select_Charmap(face, FT_ENCODING_BIG5)`
- Glyph transformations
	- Set transformation: `FT_Set_Transform(face, &matrix, &delta)`
##### Tutorial 2
- Managing glyph:
	- Extracting the glyph image: `FT_Get_Glyph(face->glyph, &glyph)`
	- Transforming the glyph image: `FT_Glyph_Transform(glyph, 0, &delta)`
	- Copying the glyph image: `FT_Glyph_Copy(glyph, &glyph2)`
	- Measuring the glyph image: `FT_Glyph_Get_Cbox(glyph, _bbox_mode_, &bbox)`
	- Converting the glyph image: `FT_Glyph_To_Bitmap(&glyph, render_mode, &origin, 1)`
- Global glyph metrics:
	- Load additional metrics via file: `FT_Attach_File`
	- Load additional metrics via stream: `FT_Attach_Stream`
	- Retrieve kerning information: `FT_Get_Kerning(face, left, right, kerning_mode, &kerning)`

Luckily some library provide example, sometimes quite advanced, that you can use to gather interesting function but also understand what a function do. In our case, FreeType have a very interesting folder called [ft2demos](https://download.savannah.gnu.org/releases/freetype/) which contains a lot of complete example usage of the library. In this article, we will use those examples to gain better understanding of function usage, but you can use example to list functions too.

Now that we have this list it gives us a pretty solid starting point but unfortunately it does not cover the entire library. In order to achieve the deepest coverage possible we are going to look into the library [API documentation](https://freetype.org/freetype2/docs/reference/index.html). This part is time consuming but finding bugs with our super harness is definitely worthy!

#### API
Another great place to look for information about library function is the API documentation. In theory all the function would be documented, allowing us the manually craft a very thorough harness.
##### Core API
- Face Creation
	- `FT_New_Face`: Call FT_Open_Face to open a font by its pathname.
	- `FT_Done_Face`: Discard a given face object, as well as all of its child slots and sizes.
	- `FT_Reference_Face`: A counter gets initialized to 1 at the time an FT_Face structure is created. This function increments the counter. FT_Done_Face then only destroys a face if the counter is 1, otherwise it simply decrements the counter.
	- `FT_New_Memory_Face`: Call FT_Open_Face to open a font that has been loaded into memory.
	- `FT_Face_Properties`: Set or override certain (library or module-wide) properties on a face-by-face basis. Useful for finer-grained control and avoiding locks on shared structures (threads can modify their own faces as they see fit).
	- `FT_Open_Face`: Create a face object from a given resource described by FT_Open_Args.
	- `FT_Attach_File`: Call FT_Attach_Stream to attach a file.
	- `FT_Attach_Stream`: ‘Attach’ data to a face object. Normally, this is used to read additional information for the face object. For example, you can attach an AFM file that comes with a Type 1 font to get the kerning values and other metrics.
- Font Testing Macros
	- `FT_HAS_HORIZONTAL`: check for horizontal metrics
	- `FT_HAS_VERTICAL`: check for vertical metrics
	- `FT_HAS_KERNING`: check if a face contains kerning data that can be accessed by `FT_Get_Kerning`
	- `FT_HAS_FIXED_SIZES`: check if a face contains embedded bitmaps
	- `FT_HAS_GLYPH_NAMES`: check if a face contains some glyph names
	- `FT_HAS_COLOR`: check if a face contains table for color glyphs
	- `FT_HAS_MULTIPLE_MASTERS`: check if a face contains multiple masters
	- `FT_HAS_SVG`: check if a face contains an SVG OpenType table
	- `FT_HAS_SBIX`: check if a face contains an sbix OpenType table and outline glyphs
	- `FT_HAS_SBIX_OVERLAY`: check if a face contains an sbix OpenType table with bit 1 in its flags field set
	- `FT_IS_SFNT`: check if a face contains a font whose format is based on SFNT storage scheme
	- `FT_IS_SCALABLE`: check if a face contains a scalable font face 
	- `FT_IS_FIXED_WITH`: check if a face contains a font face that contains fixed-width
	- `FT_IS_CID_KEYED`: check if a face contains a CID-keyed font
	- `FT_IS_TRICKY`: check if a face represent a tricky font
	- `FT_IS_NAMED_INSTANCE`: check if a face is a named instance of a GX or OpenType variation font 
	- `FT_IS_VARIATION`: check if a face has been altered by  FT_Set_MM_Design_Coordinates, FT_Set_Var_Design_Coordinates, FT_Set_Var_Blend_Coordinates, or FT_Set_MM_WeightVector.
- Sizing and Scaling
	- `FT_Set_Char_Size`: Call FT_Request_Size to request the nominal size
	- `FT_Set_Pixel_Sizes`: Call FT_Request_Size to request nominal size (in pixels)
	- `FT_Request_Size`: Resize the scale of the active FT_Size object in face
	- `FT_Select_Size`: Select a bitmap strike, sets the scaling factors of the active FT_Size object in the face
	- `FT_Set_Transform`: Set the transform that is applied to the glyph images when they are loaded into a glyph slot through FT_Load_Glyph
	- `FT_Get_Transform`: returns the transformation that is applied to a glyph images when they are loaded in to a glyph slot through FT_Load_Glyph
- Glyph Retrieval
	- `FT_Load_Glyph`: Load a glyph into the glyph slot of a face object
	- `FT_Render_Glyph`: Convert a given glyph image to a bitmap
	- `FT_Get_Kerning`: Return the kerning vector between two glyphs of the same face
	- `FT_Get_Track_Kerning`: Return the track kerning for a given face object at a given size
- Character Mapping
	- `FT_Select_Charmap`: Select a given charmap by its encoding
	- `FT_Set_Charmap`: Select a given charmap for character code to glyph index mapping
	- `FT_Get_Charmap_Index`: Retrieve index of given charmap
	- `FT_Get_Char_Index`: Return the glyph index of a given character code
	- `FT_Get_First_Char`: Return the first character code in the current charmap
	- `FT_Get_Next_Char`: Return the next character code in the current charmap
	- `FT_Load_Char`: Load a glyph into the glyph slot of a face object accessed  by its char code
- Information Retrieval
	- `FT_Get_Name_Index`: Return the glyph index of a given glyph name
	- `FT_Get_Glyph_Name`: Retrieve the ASCII name of a given glyph face
	- `FT_Get_Postscript_Name`: Retrieve the ASCII postscript name of a given face
	- `FT_Get_FSType_Flags`: Return the fsType flags for a font
	- `FT_Get_SubGlyph_Info`: Retrieve a description of a given subglyph
##### Extended API
- Unicode Variation Sequences
	- `FT_Face_GetCharVariantIndex`: Return the glyph index of a given character code as modified by the variation selector
	- `FT_Face_GetCharVariantIsDefault`: Check whether this variation of this Unicode character is the one to be found in the charmap
	- `FT_Face_GetVariantSelectors`: Return a zero-terminated list of Unicode variation selectors found in the font
	- `FT_Face_GetVariantsOfChar`: Return a zero-terminated Unicode variation selectors found for the specified character code
	- `FT_Face_GetCharsOfVariant`: Return a zero -terminated list of Unicode characters codes found for the specified variation selector
- Glyph Color Management
	- `FT_Palette_Data_Get`: Retrieve the face color palette data
	- `FT_Palette_Select`: This function has two purposes: It activates a palette for rendering / It retrieves all (unmodified) color entries of this palette. The function returns a read/write array which means that a calling application can modify the palette entries on demand.
	- `FT_Palette_Set_Foreground_Color`: `COLR` uses palette index 0xFFF to indicate a text foreground color. This function sets this value
- Glyph Layer Management
	- `FT_Get_Color_Glyph_Layer`: This is an interface for the 'COLR' v1 table in OpenType fonts to iteratively retrieve colored glyph layers associated with the current glyph slot
	- `FT_Get_Color_Glyph_Paint`: Starting point and interface to color gradient information in a 'COLR' v1 table in OpenType fonts to retrieve the paints tables for the directed acyclic graph.
	- `FT_Get_Color_Glyph_ClipBox`: Search for a 'COLR' v1 clip box for the specified base_glyph and fill the clip_box parameter with the information
	- `FT_Get_Paint_Layer`: Access the layers of `PaintColrLayers` table
	- `FT_Get_Colorline_Stops`: This is an interface to color gradient information in a 'COLR' v1 table, retrieving the gradient and solid fill information
	- `FT_Get_Paint`: Access the details of a paint using an `FT_OpaquePaint `object
- Glyph Management
	- `FT_New_Glyph`: Create a new empty glyph image
	- `FT_Get_Glyph`: Extract a glyph image from a slot
	- `FT_Glyph_Copy`: Copy a glyph image
	- `FT_Glyph_Transform`: Transform a glyph image if its format is scalable
	- `FT_Glyph_Get_CBox`: Return a glyph control box
	- `FT_Glyph_To_Bitmap`: Convert a given glyph object to a bitmap glyph object
	- `FT_Done_Glyph` destroy a given glyph

# Write a harness
##  Harness Tutorial 1
Our first harness will be using function collected from the tutorial 1:
- `FT_Init_Freetype`
- `FT_New_Face`
- `FT_Set_Char_Size`
- `FT_Set_Pixel_Sizes`
- `FT_Get_Char_Index`
- `FT_Load_Glyph`
- `FT_Render_Glyph`
- `FT_Set_Transform`

```c
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

```

This harness, despite trivial, is a perfectly good example of what you can code to start fuzzing a library. It contains interesting function for AFL to explore that could contains potential bugs.

##  Harness Tutorial 2
Our second harness will be using function collected from the tutorial 2:
- `FT_Init_Freetype`
- `FT_New_Face`
- `FT_Get_Char_Index`
- `FT_Get_Glyph`
- `FT_Glyph_Copy`
- `FT_Glyph_Transform`
- `FT_Glyph_Get_CBox`
- `FT_Get_Kerning`

```c
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
```


##  Harness API
There is multiple way to write harnesses. You can choose to write one **BIG** harness that use a lot (or every) functions, or you can group some functions together. We are going to do both: 
- A relatively small harness per API sub-topic
- A medium harness per API
- A **large** harness with every functions
### API Sub-topic harnesses
#### Core API
##### Font Testing Macros harness
```c
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
```

##### Sizing and scaling
```c
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
```
##### Glyph Retrieval
```c
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
```
##### Character Mapping
```c
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <ft2build.h>
#include <math.h>
#include FT_FREETYPE_H
#include FT_GLYPH_H

#define NUM_ENCODINGS (sizeof(supported_encodings) / sizeof(supported_encodings[0])) // trick to randomly choose encoding

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
FT_UInt agindex; 
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
    
    // Character testing
    FT_Select_Charmap(face, supported_encodings[rand() % NUM_ENCODINGS]);
    FT_Set_Charmap(face, 0);
    FT_Get_Charmap_Index(face->charmap);
    FT_Get_Char_Index(face, (FT_ULong) rand() % 256); // Little trick to cover all extended ASCII possibilities
    FT_Get_First_Char(face, &agindex);
    FT_Get_Next_Char(face, (FT_ULong) rand() % 256, &agindex);
    FT_Load_Char(face, (FT_ULong) rand() % 256, FT_LOAD_DEFAULT);

    // Cleanup
    FT_Done_Face(face);
    }

// Cleanup
FT_Done_FreeType(library);
return 0;

}
```
##### Information Retrieval
```c
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
FT_String*  glyph_name;
FT_Pointer buffer;

// For each subglyph (you need to know how many there are)
FT_UInt index;
FT_Int p1, p2;
FT_UInt flags;
FT_Matrix matrix;

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
    
    FT_Load_Glyph(face, (FT_UInt) rand() % 256, FT_LOAD_NO_SCALE);


    // Info retrieval testing
    if FT_HAS_GLYPH_NAMES(face) {
    FT_Get_Name_Index(face, glyph_name);
    FT_Get_Glyph_Name(face, (FT_UInt) rand() % 256, buffer, (FT_UInt) 256);
    }
    
    FT_Get_Postscript_Name(face);
    FT_Get_FSType_Flags(face);
    FT_Get_SubGlyph_Info(face->glyph, (FT_Int) rand() % 256, &index, &flags, 
                                     &p1, &p2, &matrix);
    // Cleanup
    FT_Done_Face(face);
    }

// Cleanup
FT_Done_FreeType(library);
return 0;

}
```
#### Extended API
##### Unicode variation sequences
```c
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <ft2build.h>
#include <math.h>
#include <stdbool.h>
#include FT_FREETYPE_H
#include FT_GLYPH_H

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FT_Library library;  // handle to library 
    FT_Face face;       // handle to face object 
    FT_Error error;     // handle to error

    // Init library
    error = FT_Init_FreeType(&library);
    if (error) {
        return 0;  // Silent failure in fuzzer
    }

    error = FT_New_Memory_Face(library,
                              data,    /* first byte in memory */
                              size,    /* size in bytes        */
                              0,       /* face_index           */
                              &face);
    if (error) {
        FT_Done_FreeType(library);
        return 0;
    }
    
    // Unicode variation testing
    const FT_UInt32* selectors = FT_Face_GetVariantSelectors(face);
    if (!selectors) { // If no valid selectors, test with a range of variation selectors
        for (FT_ULong variant_selector = 0xFE00; variant_selector <= 0xFE0F; ++variant_selector) { // First try getting chars for this variant
            const FT_UInt32* charcodes = FT_Face_GetCharsOfVariant(face, variant_selector);
            if (charcodes) { // Test existing characters that support this variant
                for (const FT_UInt32* charcode = charcodes; *charcode != 0; ++charcode) {
                    FT_UInt glyph_index = FT_Face_GetCharVariantIndex(face, *charcode, variant_selector);
                    bool is_default = FT_Face_GetCharVariantIsDefault(face, *charcode, variant_selector);
                    const FT_UInt32* chars_of_variant = FT_Face_GetCharsOfVariant(face, variant_selector);
                }
            } else {
                for (FT_ULong charcode = 0x0041; charcode <= 0x005A; ++charcode) { // Test a range of basic Latin characters
                    FT_UInt glyph_index = FT_Face_GetCharVariantIndex(face, charcode, variant_selector);
                    bool is_default = FT_Face_GetCharVariantIsDefault(face, charcode, variant_selector);
                    const FT_UInt32* chars_of_variant = FT_Face_GetCharsOfVariant(face, variant_selector);

                }
            }
        }
    } else {
        for (const FT_UInt32* sel = selectors; *sel != 0; ++sel) {  // Test with all available selectors
            FT_ULong variant_selector = (FT_ULong)*sel;
            const FT_UInt32* charcodes = FT_Face_GetCharsOfVariant(face, variant_selector);
            
            if (charcodes) {
                for (const FT_UInt32* charcode = charcodes; *charcode != 0; ++charcode) { // Test existing characters that support this variant
                    FT_UInt glyph_index = FT_Face_GetCharVariantIndex(face, *charcode, variant_selector);
                    bool is_default = FT_Face_GetCharVariantIsDefault(face, *charcode, variant_selector);
                    const FT_UInt32* variants = FT_Face_GetVariantsOfChar(face, *charcode);
                    const FT_UInt32* chars_of_variant = FT_Face_GetCharsOfVariant(face, variant_selector);
                }
            } else {
                for (FT_ULong charcode = 0x0041; charcode <= 0x005A; ++charcode) { // Test a range of basic Latin characters
                    FT_UInt glyph_index = FT_Face_GetCharVariantIndex(face, charcode, variant_selector);
                    bool is_default = FT_Face_GetCharVariantIsDefault(face, charcode, variant_selector);
                    const FT_UInt32* variants = FT_Face_GetVariantsOfChar(face, charcode);
                    const FT_UInt32* chars_of_variant = FT_Face_GetCharsOfVariant(face, variant_selector);
                }
            }
        }
    }

    // Cleanup
    FT_Done_Face(face);
    FT_Done_FreeType(library);
    return 0;
}
```

##### Glyphs color management
```c
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <ft2build.h>
#include <math.h>
#include <stdbool.h>
#include FT_FREETYPE_H
#include FT_COLOR_H

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FT_Library library;
    FT_Face face;
    FT_Error error;

    // Init library
    error = FT_Init_FreeType(&library);
    if (error) {
        return 0;
    }

    // Create new face from fuzzer data
    error = FT_New_Memory_Face(library,
                              data,
                              size,
                              0,
                              &face);
    if (error) {
        FT_Done_FreeType(library);
        return 0;
    }

    // Test palette data retrieval
    FT_Palette_Data palette_data;
    error = FT_Palette_Data_Get(face, &palette_data);
    if (!error) {
        // If we have valid palette data, test each palette
        for (FT_UShort palette_index = 0; 
             palette_index < palette_data.num_palettes; 
             palette_index++) {
            
            // Array to store palette colors
            FT_Color* colors;
            
            // Test palette selection and color retrieval
            error = FT_Palette_Select(face, palette_index, &colors);
            if (!error && colors) {
                // Modify some colors to test write access
                for (FT_UShort color_index = 0; 
                     color_index < palette_data.num_palette_entries; 
                     color_index++) {
                    
                    // Modify colors (just for testing)
                    colors[color_index].red = data[color_index % size];
                    colors[color_index].green = data[(color_index + 1) % size];
                    colors[color_index].blue = data[(color_index + 2) % size];
                    colors[color_index].alpha = data[(color_index + 3) % size];
                }
            }
        }

        // Test setting foreground colors
        if (size >= 4) {
            // Create a color from fuzzer data
            FT_Color foreground_color = {
                .red = data[0],
                .green = data[1],
                .blue = data[2],
                .alpha = data[3]
            };
            
            // Set foreground color for COLR - pass the structure directly
            error = FT_Palette_Set_Foreground_Color(face, foreground_color);
        }
    }

    // Cleanup
    FT_Done_Face(face);
    FT_Done_FreeType(library);
    return 0;
}
```


### API harnesses
#### Core API
```c
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
```

#  Improving harness

We can improve drastically the speed of execution of our harness by using AFL++ [persistent mode](https://github.com/AFLplusplus/AFLplusplus/tree/stable/utils/persistent_mode) to pass input from memory instead of using File I/O.

**LLVMTestOneInput**
```c
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>


int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {

    return 0;
}

```

**AFL Persistent mode**
```c
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

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

size_t        len;                        /* how much input did we read? */
unsigned char *buf;                        /* test case buffer pointer    */

buf = __AFL_FUZZ_TESTCASE_BUF; 

while (__AFL_LOOP(UINT_MAX)) {
    len = __AFL_FUZZ_TESTCASE_LEN; 
    if (len < 8) { continue; } // Check len minimum size
}

return 0;

}
```

This allows our harness to go from 5000 exec/sec to 40000 exec/sec ! 


