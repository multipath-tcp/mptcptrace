/*
 * timingTools.h
 *
 *  Created on: Jan 9, 2014
 *      Author: Benjamin Hesmans
 */

#ifndef TIMINGTOOLS_H_
#define TIMINGTOOLS_H_

#define US_PER_SEC 1000000	/* microseconds per second */

void tv_sub(struct timeval *plhs, struct timeval rhs);
int tv_cmp(struct timeval lhs, struct timeval rhs);

#endif /* TIMINGTOOLS_H_ */
