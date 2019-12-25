/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Math Implementation
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "math.h"

// Recursive function that returns square root
// of a number with precision upto 5 decimal places
double Square(double n, double i, double j)
{
	double mid = (i + j) / 2;
	double mul = mid * mid;

	if ((mul - n)*(mul - n) < (SQRT_PRECISION * SQRT_PRECISION))
	{
		return mid;
	}
	else if (mul < n)
	{
		return Square(n, mid, j);
	}
	else
	{
		return Square(n, i, mid);
	}
}

	// Function to find the square root of n 
double my_sqrt(double n) 
{
	// While the square root is not found 
	for(double i = 1.0; true; i++)
	{
		if ((i - n)*(i - n) < (SQRT_PRECISION * SQRT_PRECISION))
		{
			// If n is a perfect square 
			return i;
		}
		else if (i * i > n)
		{
			// Square root will lie in the interval i-1 and i
			return Square(n, i - 1, i);
		}
		i++;
	}
} 