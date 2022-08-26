#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <xtables.h>
#include <limits.h> /* INT_MAX in ip_tables.h */
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter/nf_nat.h>

#ifndef NF_NAT_RANGE_PROTO_RANDOM_FULLY
#define NF_NAT_RANGE_PROTO_RANDOM_FULLY (1 << 4)
#endif

enum {
	O_TO_SRC = 0,
	O_TO_GW,
};

static void TEE2_help(void)
{
	printf(
"TEE2 target options:\n"
" --change-dst [<ipaddr>]\n"
"				Address to map source to.\n"
" --to-gw <port>[-<port>]\n"
"				Address to mirror packet to.\n");
}

static const struct xt_option_entry TEE2_opts[] = {
	{.name = "to-source", .id = O_TO_SRC, .type = XTTYPE_STRING},
	{.name = "to-gw", .id = O_TO_GW, .type = XTTYPE_STRING},
	XTOPT_TABLEEND,
};

static void parse_to(const char *orig_arg, struct nf_nat_ipv4_multi_range_compat *mr, int type)
{
	char *arg, *dash, *error;
	const struct in_addr *ip;

	arg = strdup(orig_arg);
	if (arg == NULL)
		xtables_error(RESOURCE_PROBLEM, "strdup");

	mr->range[0].flags |= NF_NAT_RANGE_MAP_IPS;

	ip = xtables_numeric_to_ipaddr(arg);
	if (!ip)
		xtables_error(PARAMETER_PROBLEM, "Bad IP address \"%s\"\n",
			   arg);
	if (type == 0) {
		mr->range[0].min_ip = ip->s_addr;
	} else {
		mr->range[0].max_ip = ip->s_addr;
	}

	free(arg);
}

static void TEE2_init(struct xt_entry_target *t)
{
	struct nf_nat_ipv4_multi_range_compat *mr = (struct nf_nat_ipv4_multi_range_compat *)t->data;

	/* Actually, it's 0, but it's ignored at the moment. */
	mr->rangesize = 1;
}

static void TEE2_parse(struct xt_option_call *cb)
{
	const struct ipt_entry *entry = cb->xt_entry;
	int portok;
	struct nf_nat_ipv4_multi_range_compat *mr = cb->data;

	if (entry->ip.proto == IPPROTO_TCP
	    || entry->ip.proto == IPPROTO_UDP
	    || entry->ip.proto == IPPROTO_SCTP
	    || entry->ip.proto == IPPROTO_DCCP
	    || entry->ip.proto == IPPROTO_ICMP)
		portok = 1;
	else
		portok = 0;

	xtables_option_parse(cb);
	switch (cb->entry->id) {
	case O_TO_SRC:
		parse_to(cb->arg, mr, 0);
		break;
	case O_TO_GW:
		parse_to(cb->arg, mr, 1);
		break;
	}
}

static void
TEE2_print(const void *ip, const struct xt_entry_target *target,
                 int numeric)
{
	const struct nf_nat_ipv4_multi_range_compat *mr = (const void *)target->data;
	const struct nf_nat_ipv4_range *r = &mr->range[0];

	if (r->flags & NF_NAT_RANGE_MAP_IPS) {
		struct in_addr a;

		a.s_addr = r->min_ip;
		printf(" to:%s", xtables_ipaddr_to_numeric(&a));
		a.s_addr = r->max_ip;
		printf(" change src to:%s", xtables_ipaddr_to_numeric(&a));
	}
}

static void
TEE2_save(const void *ip, const struct xt_entry_target *target)
{
	const struct nf_nat_ipv4_multi_range_compat *mr = (const void *)target->data;
	const struct nf_nat_ipv4_range *r = &mr->range[0];

	if (r->flags & NF_NAT_RANGE_MAP_IPS) {
		struct in_addr a;

		a.s_addr = r->min_ip;
		printf(" --to-gw %s", xtables_ipaddr_to_numeric(&a));
		a.s_addr = r->max_ip;
		printf(" --to-source %s", xtables_ipaddr_to_numeric(&a));
	}

}

static struct xtables_target TEE2_tg_reg = {
	.name		= "TEE2",
	.revision   = 1,
	.version	= XTABLES_VERSION,
	.family		= NFPROTO_IPV4,
	.size		= XT_ALIGN(sizeof(struct nf_nat_ipv4_multi_range_compat)),
	.userspacesize	= XT_ALIGN(sizeof(struct nf_nat_ipv4_multi_range_compat)),
	.help		= TEE2_help,
	.init		= TEE2_init,
	.x6_parse	= TEE2_parse,
	.print		= TEE2_print,
	.save		= TEE2_save,
	.x6_options	= TEE2_opts,
};

void _init(void)
{
	xtables_register_target(&TEE2_tg_reg);
}
