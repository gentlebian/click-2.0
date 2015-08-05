/*
 * iprewriter.{cc,hh} -- rewrites packet source and destination
 * Max Poletto, Eddie Kohler
 *
 * Copyright (c) 2000 Massachusetts Institute of Technology
 * Copyright (c) 2008-2010 Meraki, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, subject to the conditions
 * listed in the Click LICENSE file. These conditions include: you must
 * preserve this copyright notice, and you cannot mention the copyright
 * holders in advertising related to the Software without their permission.
 * The Software is provided WITHOUT ANY WARRANTY, EXPRESS OR IMPLIED. This
 * notice is a summary of the Click LICENSE file; the license in that file is
 * legally binding.
 */

#include <click/config.h>
#include "iprewriter.hh"
#include <clicknet/ip.h>
#include <clicknet/tcp.h>
#include <clicknet/udp.h>
#include <click/args.hh>
#include <click/straccum.hh>
#include <click/error.hh>
#include <click/timer.hh>
#include <click/router.hh>
// other includes for using socket
#include <fstream>
#include <iostream>
//#include <string>
//#include <click/string>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <mysql/mysql.h>

using namespace std;

CLICK_DECLS

IPRewriter::IPRewriter()
    : _udp_map(0)
{
}

IPRewriter::~IPRewriter()
{
}

void *
IPRewriter::cast(const char *n)
{
    if (strcmp(n, "IPRewriterBase") == 0)
	return (IPRewriterBase *)this;
    else if (strcmp(n, "TCPRewriter") == 0)
	return (TCPRewriter *)this;
    else if (strcmp(n, "IPRewriter") == 0)
	return this;
    else
	return 0;
}

int
IPRewriter::configure(Vector<String> &conf, ErrorHandler *errh)
{
	String server, user, passwd, database;

    _udp_timeouts[0] = 60 * 5;	// 5 minutes
    _udp_timeouts[1] = 5;	// 5 seconds

	backup = false;
    restored = false;

    if (Args(this, errh).bind(conf)
	.read("UDP_TIMEOUT", SecondsArg(), _udp_timeouts[0])
	.read("UDP_GUARANTEE", SecondsArg(), _udp_timeouts[1])
/*added to configure database connection*/
	.read("BACK_UP", backup)
	.read("RESTORE", restored)
	.read_p("SERVER", server)
	.read_p("DATABASE", database)
	.read_p("RW_ID", user) 
	.read_p("RW_PASSWD", passwd) 
/*end of connection configuration*/
	.consume() < 0)
	return -1;

    _udp_timeouts[0] *= CLICK_HZ; // change timeouts to jiffies
    _udp_timeouts[1] *= CLICK_HZ;

	_server	  = server;
	_database = database;
	_user	  = user;
	_passwd	  = passwd;

	// added because of backup
	if(backup)
		init_connection();

    return TCPRewriter::configure(conf, errh);
}

inline IPRewriterEntry *
IPRewriter::get_entry(int ip_p, const IPFlowID &flowid, int input)
{
    if (ip_p == IP_PROTO_TCP)
	return TCPRewriter::get_entry(ip_p, flowid, input);
    if (ip_p != IP_PROTO_UDP)
	return 0;
    IPRewriterEntry *m = _udp_map.get(flowid);
    if (!m && (unsigned) input < (unsigned) _input_specs.size()) {
	IPRewriterInput &is = _input_specs[input];
	IPFlowID rewritten_flowid = IPFlowID::uninitialized_t();
	if (is.rewrite_flowid(flowid, rewritten_flowid, 0, IPRewriterInput::mapid_iprewriter_udp) == rw_addmap)
	    m = IPRewriter::add_flow(0, flowid, rewritten_flowid, input);
    }
    return m;
}
// add flow into _udp_map and return IPRewriterEntry. called by push
IPRewriterEntry *
IPRewriter::add_flow(int ip_p, const IPFlowID &flowid,
		     const IPFlowID &rewritten_flowid, int input)
{
    if (ip_p == IP_PROTO_TCP)
	return TCPRewriter::add_flow(ip_p, flowid, rewritten_flowid, input);

    void *data;
    if (!(data = _udp_allocator.allocate()))
	return 0;

    IPRewriterFlow *flow = new(data) IPRewriterFlow
	(flowid, _input_specs[input].foutput,
	 rewritten_flowid, _input_specs[input].routput, ip_p,
	 !!_udp_timeouts[1], click_jiffies() + relevant_timeout(_udp_timeouts),
	 this, input);

    return store_flow(flow, input, _udp_map, &reply_udp_map(input));
}

void
IPRewriter::push(int port, Packet *p_in)
{
    WritablePacket *p = p_in->uniqueify();
    click_ip *iph = p->ip_header();

/*#########################*/
	if(restored){
		restore();
		restored = false;
	} 
/*#########################*/

    // handle non-first fragments
    if ((iph->ip_p != IP_PROTO_TCP && iph->ip_p != IP_PROTO_UDP) //iprewriter only handles tcp/udp packets, for others just push out
	|| !IP_FIRSTFRAG(iph)
	|| p->transport_length() < 8) {
	const IPRewriterInput &is = _input_specs[port];
	if (is.kind == IPRewriterInput::i_nochange)
	    output(is.foutput).push(p);// don't quite understand here, need to make sure if go into here.
	else
	    p->kill();
	return;
    }

    IPFlowID flowid(p);
    HashContainer<IPRewriterEntry> *map = (iph->ip_p == IP_PROTO_TCP ? &_map : &_udp_map);
    IPRewriterEntry *m = map->get(flowid);

    if (!m) {			// create new mapping
	IPRewriterInput &is = _input_specs.at_u(port); //get the pattern
	IPFlowID rewritten_flowid = IPFlowID::uninitialized_t(); //get uninitialized flowid
	int result = is.rewrite_flowid(flowid, rewritten_flowid, p, iph->ip_p == IP_PROTO_TCP ? 0 : IPRewriterInput::mapid_iprewriter_udp); //make the rewritten_flowid accordingly.
	if (result == rw_addmap) //when the add map situation happens
	    m = IPRewriter::add_flow(iph->ip_p, flowid, rewritten_flowid, port);
	if (!m) {
	    checked_output_push(result, p);// if not success to add into flowtable, just push it out as specified. 
	    return;
	} else if (_annos & 2)
	    m->flow()->set_reply_anno(p->anno_u8(_annos >> 2));
	
		// sent newly added mapping to database
		remote_copy_flow(iph->ip_p, flowid, rewritten_flowid, port);
		//remote_del_flow(iph->ip_p, flowid);
    }
	// set the expiry time;
    click_jiffies_t now_j = click_jiffies();
    IPRewriterFlow *mf = m->flow();
    if (iph->ip_p == IP_PROTO_TCP) {
	TCPFlow *tcpmf = static_cast<TCPFlow *>(mf);
	tcpmf->apply(p, m->direction(), _annos);
	if (_timeouts[1])
	    tcpmf->change_expiry(_heap, true, now_j + _timeouts[1]);
	else
	    tcpmf->change_expiry(_heap, false, now_j + tcp_flow_timeout(tcpmf));
    } else {
	mf->apply(p, m->direction(), _annos);
	mf->change_expiry_by_timeout(_heap, now_j, _udp_timeouts);
    }
	//NOT SURE WHAT THIS DO, NEED TO KNOW!
    output(m->output()).push(p);

}

String
IPRewriter::udp_mappings_handler(Element *e, void *)
{
    IPRewriter *rw = (IPRewriter *)e;
    click_jiffies_t now = click_jiffies();
    StringAccum sa;
    for (Map::iterator iter = rw->_udp_map.begin(); iter.live(); ++iter) {
	iter->flow()->unparse(sa, iter->direction(), now);
	sa << '\n';
    }
    return sa.take_string();
}

void
IPRewriter::add_handlers()
{
    add_read_handler("tcp_mappings", tcp_mappings_handler);
    add_read_handler("udp_mappings", udp_mappings_handler);
    add_rewriter_handlers(true);
}

/* background unit to copy and send flow to remote database */
void 
IPRewriter::init_connection(){

conn = mysql_real_connect(&mysql, _server.c_str(), _user.c_str(),
							  _passwd.c_str(), _database.c_str(), 3306,
							  0, 0);
	if( conn == NULL )
		cout << "connection to database failed" << endl;
}

void 
IPRewriter::destroy_connection(){
	mysql_close(conn);
}

void 
IPRewriter::remote_copy_flow(int ip_p, IPFlowID &flowid, IPFlowID &rewritten_flowid, int port){
	int res;
	string query("INSERT INTO ftable (pro, saddr, sport, daddr, dport, _saddr, _sport, _daddr, _dport, port) VALUES ( '");
	stringstream s;
	// If connection failed, return;
	if(conn==NULL) {
		cout << "connection not set up" << endl;
		return;
	}

	// Marshall parameters into query string
	s << query  << ip_p << "', '" << flowid.saddr() << "', '" << flowid.sport() << "', '"<< flowid.daddr() << "', '" << flowid.dport() << "', '";
	s << rewritten_flowid.saddr() << "', '" << rewritten_flowid.sport() << "', '" << rewritten_flowid.daddr() << "', '" << rewritten_flowid.dport() << "', '";
	s << port << "' )";

	// Send the insert query
	string tmp = s.str();
	res = mysql_query(conn, tmp.c_str());
	if(res != 0){
		cout << "copy failed" << endl;
		return;
	}

}

void 
IPRewriter::remote_del_flow(int ip_p, IPFlowID flowid){
	int res;
	string query("DELETE FROM ftable WHERE ");
	stringstream s;

	if(conn==NULL) {
        cout << "connection not set up" << endl;
        return;
    }

	// Marshall parameters into query string
	s << query << "pro = '" << ip_p;
	s << "' AND saddr = '" << flowid.saddr() << "' AND sport = '" << flowid.sport();
	s << "' AND daddr = '" << flowid.daddr() << "' AND dport = '" << flowid.dport();
	s << "'";

	// Send the delete query
	res = mysql_query(conn, s.str().c_str()); 
	if(res != 0){
		cout << "remote deleting failed" << endl;
		return;
	}
}

void IPRewriter::restore(){
	int res;
	MYSQL_RES *result;
	MYSQL_ROW row;

	// check connection, if not connected initialize.
	if(conn==NULL) {
		init_connection();
		if( conn==NULL ){
	        cout << "connection not set up" << endl;
    	    return;
		}
    }

	// Fetch flow info from database and add into flow tables.
	res = mysql_query(conn, "SELECT * FROM ftable");
	if(res != 0){
		cout << "fetching result failed" << endl;
		return;
	}

	result = mysql_store_result(conn);

	// Add flow row by row
	while((row = mysql_fetch_row(result))){
	// add_flow(iph->ip_p, flowid, rewritten_flowid, port);
	
		IPRewriter :: add_flow((uint8_t)atoi(row[0]), 
							*(new IPFlowID(atoi(row[1]), (short)(atoi(row[2])), atoi(row[3]), (short)(atoi(row[4])))), 
							*(new IPFlowID(atoi(row[5]), (short)(atoi(row[6])), atoi(row[7]), (short)(atoi(row[8])))), 
							atoi(row[9]));
	}
	
	cout << "finished initialization" << endl;
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(TCPRewriter UDPRewriter)
EXPORT_ELEMENT(IPRewriter)
