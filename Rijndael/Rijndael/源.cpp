/*---AES---*/
#include<stdio.h>
#include<stdlib.h>
#include <string.h>

#define Nk 4
#define Nb 4
#define Nr 10
#define xtime(x)   ((x << 1) ^ (((x >> 7) & 1) * 0x1b))
#define Multiply(x,y) (((y & 1) * x) ^ ((y>>1 & 1) * xtime(x)) ^ ((y>>2 & 1) * xtime(xtime(x))) ^ ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^ ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))))

//DataSize : 128bits 	KeySize : 128bits
// data :  
unsigned char data[4][4];
unsigned char key[16];
unsigned int W[Nb * (Nr + 1)] = { 0 }, Inv_W[Nb * (Nr + 1)] = { 0 };
// Encryption or Decryption
int en_be;
// address of openFile and saveFile
char openFile[100], saveFile[100];

struct proccessKey
{
	int en_beP;
	unsigned char keyP[16];
	char open[100], save[100];
};

// S BOX
unsigned char sbox[16][16] = {
	0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
	0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
	0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
	0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
	0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
	0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
	0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
	0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
	0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
	0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
	0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
	0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
	0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
	0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
	0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
	0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

// Inv_S BOX
unsigned char Inv_sbox[16][16] = {
	0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
	0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
	0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
	0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
	0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
	0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
	0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
	0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
	0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
	0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
	0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
	0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
	0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
	0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
	0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

extern "C" _declspec(dllexport) int RijndaelProccess(proccessKey *block);
//extern "C" _declspec(dllexport) int sum(int a, int b);

int readFile();
//Encryption Function
void Rijndael();
void ByteSub(unsigned char Temdata[][4]);
void ShiftRow(unsigned char Temdata[][4]);
void MixColumn(unsigned char Temdata[][4]);
void KeyExpansion(unsigned char Temkey[], unsigned int WKey[]);
unsigned int SubByte(unsigned int Temp);
//Becryption Function
void Inv_Rijndael();
void Inv_ByteSub(unsigned char Temdata[][4]);
void Inv_ShiftRow(unsigned char Temdata[][4]);
void Inv_MixColumn(unsigned char Temdata[][4]);
void Inv_KeyExpansion(unsigned char Temkey[], unsigned int WKey[]);
unsigned int Inv_SubByte(unsigned int Temp);
/////////////
unsigned int Rotl(unsigned int Temp);
void AddRoundKey(unsigned char Temdata[][4], unsigned int Temkey[]);
void DateChange(unsigned int W[], unsigned char Temdata[][4]);
void DataBack(unsigned int W[], unsigned char Temdata[][4]);

int RijndaelProccess(proccessKey *block)
{
	en_be = block->en_beP;
	strcpy_s(openFile, block->open);
	strcpy_s(saveFile, block->save);
	for (int i = 0; i < 16; i++)
		key[i] = block->keyP[i];

	int symbol = readFile();

	return symbol;
}

// Encryption
void Rijndael()
{
	KeyExpansion(key, W);
	AddRoundKey(data, W);
	for (int i = 1; i < Nr; i++)
	{
		//Round
		ByteSub(data);
		ShiftRow(data);
		MixColumn(data);
		AddRoundKey(data, &W[i * 4]);
	}

	//FinalRound
	ByteSub(data);
	ShiftRow(data);
	AddRoundKey(data, &W[Nr * 4]);
}

// Decryption
void Inv_Rijndael()
{
	Inv_KeyExpansion(key, W);
	AddRoundKey(data, &W[Nr * 4]);
	for (int i = Nr - 1; i > 0; i--)
	{
		//Round
		Inv_ByteSub(data);
		Inv_ShiftRow(data);
		Inv_MixColumn(data);
		AddRoundKey(data, &W[i * 4]);
	}

	//FinalRound
	Inv_ByteSub(data);
	Inv_ShiftRow(data);
	AddRoundKey(data, W);
}

/*---Key expansion---*/
void KeyExpansion(unsigned char Temkey[], unsigned int WKey[])
{
	unsigned int temp, input;
	unsigned int Rcon[Nr + 1];
	unsigned char RC[Nr + 1];

	RC[0] = 0x01;
	Rcon[0] = RC[0];
	Rcon[0] = Rcon[0] << 24;

	for (int i = 1; i < Nr + 1; i++)
	{
		Rcon[i] = 0;
		RC[i] = xtime(RC[i - 1]);
		Rcon[i] = Rcon[i] | RC[i];
		Rcon[i] = Rcon[i] << 24;
	}

	for (int i = 0; i < 16; i += 4)
	{
		for (int j = 0; j < 4; j++)
		{
			temp = Temkey[i + j];
			WKey[i / 4] = WKey[i / 4] | temp;
			if (j<3) WKey[i / 4] = WKey[i / 4] << 8;
		}
	}

	for (int i = Nk; i < Nb * (Nr + 1); i++)
	{
		temp = WKey[i - 1];
		//printf("i = %d W[i-1]=%x\n", i, temp);
		if (i % 4 == 0) {
			input = Rotl(temp);
			temp = SubByte(input) ^ Rcon[i / Nk - 1];
		}

		WKey[i] = WKey[i - Nk] ^ temp;
	}
}

void Inv_KeyExpansion(unsigned char Temkey[], unsigned int WKey[])
{
	unsigned int temp, input;
	unsigned int Rcon[Nr + 1];
	unsigned char RC[Nr + 1];

	RC[0] = 0x01;
	Rcon[0] = RC[0];
	Rcon[0] = Rcon[0] << 24;

	for (int i = 1; i < Nr + 1; i++)
	{
		Rcon[i] = 0;
		RC[i] = xtime(RC[i - 1]);
		Rcon[i] = Rcon[i] | RC[i];
		Rcon[i] = Rcon[i] << 24;
	}

	for (int i = 0; i < 16; i += 4)
	{
		for (int j = 0; j < 4; j++)
		{
			temp = Temkey[i + j];
			WKey[i / 4] = WKey[i / 4] | temp;
			if (j<3) WKey[i / 4] = WKey[i / 4] << 8;
		}
	}

	for (int i = Nk; i < Nb * (Nr + 1); i++)
	{
		temp = WKey[i - 1];
		//printf("i = %d W[i-1]=%x\n", i, temp);
		if (i % 4 == 0) {
			input = Rotl(temp);
			temp = SubByte(input) ^ Rcon[i / Nk - 1];
		}

		WKey[i] = WKey[i - Nk] ^ temp;
	}

	unsigned char Temdata[4][4];

	for (int i = 1; i < Nr; i++)
	{
		DateChange(&WKey[i * 4], Temdata);
		Inv_MixColumn(Temdata);
		DataBack(&WKey[i * 4], Temdata);
	}
}

void DateChange(unsigned int W[], unsigned char Temdata[][4])
{
	for (int i = 0; i < 4; i++)
		for (int j = 0; j < 4; j++)
		{
			Temdata[j][i] = (W[i] >> ((3 - j) * 8)) & 0x000000ff;
		}
}

void DataBack(unsigned int W[], unsigned char Temdata[][4])
{
	for (int i = 0; i < 4; i++)
	{
		W[i] = 0;
		for (int j = 0; j < 4; j++)
		{
			W[i] = W[i] | Temdata[j][i];

			if (j < 3)	W[i] = W[i] << 8;
		}
	}
}

/*---Rotl---*/
unsigned int Rotl(unsigned int Temp)
{
	unsigned int word = 0;

	word = Temp >> 24;
	Temp = Temp << 8;
	Temp = Temp | word;

	return Temp;
}

/*---SubByte(32bits)---*/
unsigned int SubByte(unsigned int Temp)
{
	unsigned char row, col;
	unsigned int tem = 0;

	for (int i = 3; i >= 0; i--)
	{
		row = Temp >> (i * 8 + 4) & 0x0f;
		col = Temp >> (i * 8) & 0x0f;
		tem = tem | sbox[row][col];

		if (i > 0) tem = tem << 8;
	}

	return tem;
}

unsigned int Inv_SubByte(unsigned int Temp)
{
	unsigned char row, col;
	unsigned int tem = 0;

	for (int i = 3; i >= 0; i--)
	{
		row = Temp >> (i * 8 + 4) & 0x0f;
		col = Temp >> (i * 8) & 0x0f;
		tem = tem | Inv_sbox[row][col];

		if (i > 0) tem = tem << 8;
	}

	return tem;
}

/*---SubByte(8bits)---*/
void ByteSub(unsigned char Temdata[][4])
{
	unsigned char row, col;

	for (int i = 0; i < 4; i++)
		for (int j = 0; j < 4; j++)
		{
			row = Temdata[i][j] >> 4;
			col = Temdata[i][j] & 0x0f;
			Temdata[i][j] = sbox[row][col];
		}
}

void Inv_ByteSub(unsigned char Temdata[][4])
{
	unsigned char row, col;

	for (int i = 0; i < 4; i++)
		for (int j = 0; j < 4; j++)
		{
			row = Temdata[i][j] >> 4;
			col = Temdata[i][j] & 0x0f;
			Temdata[i][j] = Inv_sbox[row][col];
		}
}

/*---ShiftRow---*/
void ShiftRow(unsigned char Temdata[][4])
{
	unsigned char tem;

	for (int i = 1; i < 4; i++)
	{
		for (int n = 0; n < i; n++)//shift
		{
			tem = Temdata[i][0];

			for (int j = 0; j < 3; j++)
				Temdata[i][j] = Temdata[i][j + 1];

			Temdata[i][3] = tem;
		}
	}
}

void Inv_ShiftRow(unsigned char Temdata[][4])
{
	unsigned char tem;

	for (int i = 1; i < 4; i++)
	{
		for (int n = 0; n < (Nb - i); n++)//shift
		{
			tem = Temdata[i][0];

			for (int j = 0; j < 3; j++)
				Temdata[i][j] = Temdata[i][j + 1];

			Temdata[i][3] = tem;
		}
	}
}

/*---MixColumn---*/
void MixColumn(unsigned char Temdata[][4])
{
	unsigned char tem[4];

	for (int i = 0; i<4; i++)
	{
		//printf("%x %x %x %x	\n",Temdata[0][i],Temdata[1][i],Temdata[2][i],Temdata[3][i]);
		tem[0] = xtime(Temdata[0][i]) ^ (xtime(Temdata[1][i]) ^ Temdata[1][i]) ^ (0x01 * Temdata[2][i]) ^ (0x01 * Temdata[3][i]);
		tem[1] = (0x01 * Temdata[0][i]) ^ xtime(Temdata[1][i]) ^ (xtime(Temdata[2][i]) ^ Temdata[2][i]) ^ (0x01 * Temdata[3][i]);
		tem[2] = (0x01 * Temdata[0][i]) ^ (0x01 * Temdata[1][i]) ^ xtime(Temdata[2][i]) ^ (xtime(Temdata[3][i]) ^ Temdata[3][i]);
		tem[3] = (xtime(Temdata[0][i]) ^ Temdata[0][i]) ^ (0x01 * Temdata[1][i]) ^ (0x01 * Temdata[2][i]) ^ xtime(Temdata[3][i]);

		for (int j = 0; j < 4; j++)
			Temdata[j][i] = tem[j];
	}
}

void Inv_MixColumn(unsigned char Temdata[][4])
{
	unsigned char tem[4];

	for (int i = 0; i<4; i++)
	{
		//printf("%x %x %x %x	\n",Temdata[0][i],Temdata[1][i],Temdata[2][i],Temdata[3][i]);
		tem[0] = Multiply(Temdata[0][i], 0x0e) ^ Multiply(Temdata[1][i], 0x0b) ^ Multiply(Temdata[2][i], 0x0d) ^ Multiply(Temdata[3][i], 0x09);
		tem[1] = Multiply(Temdata[0][i], 0x09) ^ Multiply(Temdata[1][i], 0x0e) ^ Multiply(Temdata[2][i], 0x0b) ^ Multiply(Temdata[3][i], 0x0d);
		tem[2] = Multiply(Temdata[0][i], 0x0d) ^ Multiply(Temdata[1][i], 0x09) ^ Multiply(Temdata[2][i], 0x0e) ^ Multiply(Temdata[3][i], 0x0b);
		tem[3] = Multiply(Temdata[0][i], 0x0b) ^ Multiply(Temdata[1][i], 0x0d) ^ Multiply(Temdata[2][i], 0x09) ^ Multiply(Temdata[3][i], 0x0e);

		for (int j = 0; j < 4; j++)
			Temdata[j][i] = tem[j];
	}
}

/*---AddRoundKey---*/
void AddRoundKey(unsigned char Temdata[][4], unsigned int Temkey[])
{
	unsigned char tem[16];

	for (int i = 0; i<16; i++)
	{
		tem[i] = 0;
		tem[i] = (Temkey[i / 4] >> (24 - i * 8)) & 0xff;
	}

	for (int i = 0; i<4; i++)
		for (int j = 0; j<4; j++)
			Temdata[j][i] = Temdata[j][i] ^ tem[j + i * 4];
}

/*---read data of file---*/
int readFile()
{
	FILE *fp, *fps;

	// read file
	if ((fopen_s(&fp, openFile, "rb")) != 0)
	{
		fclose(fp);
		return 0;
	}

	// output file
	if ((fopen_s(&fps, saveFile, "wb")) != 0)
	{
		return 0;
	}

	while (!feof(fp))
	{
		for (int i = 0; i < 4; i++)
		{
			for (int j = 0; j < 4; j++)
			{
				if (fread(&data[j][i], sizeof(char), 1, fp) == 1)	continue;
				else if (j < 4)
				{
					for (int n = 0; n < i; n++)
					{
						for (int m = 0; m < 4; m++)
						{
							data[m][n] = data[m][n] ^ key[n * 4 + m];

							if (fwrite(&data[m][n], sizeof(char), 1, fps) != 1)
								return 0;
						}
					}

					for (int m = 0; m < j; m++)
					{
						data[m][i] = data[m][i] ^ key[i * 4 + m];

						if (fwrite(&data[m][i], sizeof(char), 1, fps) != 1)
							return 0;
					}

					fclose(fps);
					fclose(fp);
					return 1;
				}
				else return 0;
			}
		}

		if (en_be == 1)	Rijndael();
		else	Inv_Rijndael();

		for (int i = 0; i < 4; i++)
		{
			for (int j = 0; j < 4; j++)
			{
				if (fwrite(&data[j][i], sizeof(char), 1, fps) != 1)
					return 0;
			}
		}
	}

	fclose(fps);
	fclose(fp);
	return 1;
}