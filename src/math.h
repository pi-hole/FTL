/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Math Prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#ifndef MATH_H
#define MATH_H

#include <stdlib.h>
#include <stdbool.h>

#define SQRT_PRECISION 1e-5

// Recursive function that returns square root
double Square(const double n, const double i, const double j) __attribute__((const));
  
// Function to find the square root of n 
double my_sqrt(const double n) __attribute__((const));

#endif //MATH_H