#pragma once
#include "cuda_runtime.h"
#include "device_launch_parameters.h"
#include <algorithm>
#include <math.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
//#define HEX
//#define TEST
#define ISON(N, X) ((N & (1ULL << (X))) != 0)
#define ISOFF(N, X) ((N & (1ULL << (X))) == 0)
#define MAKEON(N, X) (N | (1ULL << (X)))
#define MAKEOFF(N, X) (N & ~(1ULL << (X)))