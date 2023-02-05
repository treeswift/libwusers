/**
 * This file has no copyright assigned and is placed in the public domain.
 * This file is part of the libwusers compatibility library:
 *   https://github.com/treeswift/libwusers
 * No warranty is given; refer to the LICENSE file in the project root.
 */

#ifndef _CHR_H_
#define _CHR_H_

namespace wusers_impl {
unsigned int get_cp();

void set_last_error(int last_error);
}

#endif /* !_CHR_H_ */
