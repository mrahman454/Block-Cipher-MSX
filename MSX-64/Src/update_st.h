/******************************************************************************
* 
*
* THIS CODE IS FURNISHED TO YOU "AS IS" WITHOUT WARRANTY OF ANY KIND.
*
*****************************************************************************/

#if LOOP != 0
F_PREFIX void update_st(uint32_t st[S_NUM], uint32_t idx[6])
{
	uint32_t tmp = st[idx[0]];

	// update state
	st[idx[1]] = ROL32(st[idx[1]],1) + tmp;
	st[idx[2]] = ROL32(st[idx[2]],2) + tmp;
	st[idx[3]] = ROL32(st[idx[3]],3) + tmp;
	st[idx[4]] = ROL32(st[idx[4]],4) + tmp;
	st[idx[5]] = ROL32(st[idx[5]],5) + tmp;

	// update index
	idx[0]++;
	idx[1]++;
	idx[2]++;
	idx[3]++;
	idx[4] = (idx[4]+1) % S_NUM;
	idx[5] = (idx[5]+1) % S_NUM;
}
#else

#define update_st(src, d0, d1, d2, d3, d4) \
{ \
	uint32_t tmp = st[src]; \
	st[d0] = ROL32(st[d0],1) + tmp; \
	st[d1] = ROL32(st[d1],2) + tmp; \
	st[d2] = ROL32(st[d2],3) + tmp; \
	st[d3] = ROL32(st[d3],4) + tmp; \
	st[d4] = ROL32(st[d4],5) + tmp; \
}
#endif
