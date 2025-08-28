#include "segment_utils.h"

#include <algorithm>
#include <vector>
#include <iostream>
#include "lib/openbsd-tree.h"
#include "pathd/pathd.h"


static std::vector<struct segment_t>
dump_segments(struct srte_segment_list *s_list)
{
	std::vector<struct segment_t> res;
	char buf[128];

	struct srte_segment_entry *s_entry;
	RB_FOREACH (s_entry, srte_segment_entry_head, &s_list->segments) {
		if (s_entry->segment_list == s_list) {
			struct segment_t seg = {};
			seg.index = s_entry->index;

			ipaddr2str(&s_entry->srv6_sid_value, buf, sizeof(buf));
			seg.v6Address = buf;
			res.push_back(seg);
		} else {
			std::cout
				<< "ERROR(dump_segments): segment_list_segment back pointer mismatch, at index "
				<< s_entry->index << std::endl;
		}
	}

	// sort res by index value
	std::sort(res.begin(), res.end(),
		  [](const segment_t &a, const segment_t &b) {
			  return a.index < b.index;
		  });

	return res;
}

extern struct srte_segment_list_head srte_segment_lists;

std::vector<struct segment_list_t> dump_segment_lists()
{
	std::vector<struct segment_list_t> res;
	struct srte_segment_list *s_list;

	RB_FOREACH (s_list, srte_segment_list_head, &srte_segment_lists) {
		struct segment_list_t seg_list = {};
		seg_list.name = s_list->name;
		seg_list.refCount = s_list->refcount;
		seg_list.flags = s_list->flags;
		seg_list.status = s_list->status;
		seg_list.installed = s_list->installed;
		seg_list.segments = dump_segments(s_list);
		res.push_back(seg_list);
	}

	// sort res by name
	std::sort(res.begin(), res.end(),
		  [](const segment_list_t &a, const segment_list_t &b) {
			  return strcmp(a.name.c_str(), b.name.c_str()) < 0;
		  });

	return res;
}

/*
 * Comparison
 * */
bool compare_segment_list(const struct segment_list_t &a,
			  const struct segment_list_t &b)
{
	// Grouped field comparison with full context output
	if (a.name != b.name || a.refCount != b.refCount ||
	    a.flags != b.flags || a.status != b.status) {
		std::cerr << "Mismatch in segment_list_t fields:\n"
			  << "  name:     '" << a.name << "' vs '" << b.name
			  << "'\n"
			  << "  refCount: " << a.refCount << " vs "
			  << b.refCount << "\n"
			  << "  flags:    0x" << std::hex << a.flags << " vs 0x"
			  << b.flags << "\n"
			  << "  installed: " << a.installed << " vs "
			  << b.installed << "\n"
			  << "  status:   0x" << std::hex << a.status
			  << " vs 0x" << b.status << std::dec << "\n";
		return false;
	}

	// Compare segments vector
	if (a.segments.size() != b.segments.size()) {
		std::cerr << "Mismatch: segments count (" << a.segments.size()
			  << " vs " << b.segments.size() << ")\n";
		return false;
	}

	for (size_t i = 0; i < a.segments.size(); ++i) {
		const auto &segA = a.segments[i];
		const auto &segB = b.segments[i];

		if (segA.index != segB.index) {
			std::cerr << "Mismatch in segment[" << i << "]: index ("
				  << segA.index << " vs " << segB.index
				  << ")\n";
			return false;
		}

		if (segA.v6Address != segB.v6Address) {
			std::cerr << "Mismatch in segment[" << i
				  << "]: v6Address ('" << segA.v6Address
				  << "' vs '" << segB.v6Address << "')\n";
			return false;
		}
	}

	return true;
}
