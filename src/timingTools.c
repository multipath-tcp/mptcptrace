/*
 * timingTools.c
 *
 *  Created on: Jan 9, 2014
 *      Author: Benjamin Hesmans
 */

#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include "timingTools.h"

/**
 * TCP trace substract
 */
/* subtract the rhs from the lhs, result in lhs */
void
tv_sub(struct timeval *plhs, struct timeval rhs)
{
    /* sanity check, lhs MUST BE more than rhs */
    /*if (tv_lt(*plhs,rhs)) {
	fprintf(stderr,"bad timestamp order!\n");
	plhs->tv_sec = plhs->tv_usec = 0;
	return;
    }*/

    if (plhs->tv_usec >= rhs.tv_usec) {
	plhs->tv_usec -= rhs.tv_usec;
    } else if (plhs->tv_usec < rhs.tv_usec) {
	plhs->tv_usec += US_PER_SEC - rhs.tv_usec;
	plhs->tv_sec -= 1;
    }
    plhs->tv_sec -= rhs.tv_sec;
}
/**
 * TCPtrace compare
 */
/*  1: lhs >  rhs */
/*  0: lhs == rhs */
/* -1: lhs <  rhs */
int
tv_cmp(struct timeval lhs, struct timeval rhs)
{
    if (lhs.tv_sec > rhs.tv_sec) {
    return(1);
    }

    if (lhs.tv_sec < rhs.tv_sec) {
    return(-1);
    }

    /* ... else, seconds are the same */
    if (lhs.tv_usec > rhs.tv_usec)
    return(1);
    else if (lhs.tv_usec == rhs.tv_usec)
    return(0);
    else
    return(-1);
}
