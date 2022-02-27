#include "ce_detection.h"


int main() {
	if(!ce_detection::run_common())
		ce_detection::run_advanced();
	system("pause");
}