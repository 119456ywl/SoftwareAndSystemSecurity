#include <stdio.h>

int patternCreate() {
	FILE* fp;
	int i, j, k, count;
	int err;
	if (err = fopen_s(&fp, "pattern.txt", "w") != 0) {
		return err;
	}
	count = 0;
	for (i = 'A'; i <= 'Z'; ++i) {
		for (j = 'a'; j <= 'z'; ++j) {
			for (k = '0'; k <= '9'; ++k) {
				fprintf_s(fp, "%c%c%c",i,j,k);
				count += 3;
				if (count >= 2000) break;
			}
			if (count >= 2000) break;
		}
		if (count >= 2000) break;
	}
	fclose(fp);
	return 0;
}
int main() {
	patternCreate();
	return 0;
}