// Basic routines for Paxos implementation

#include "make_unique.h"
#include "paxmsg.h"
#include "paxserver.h"
#include "log.h"

bool my_trim_func(const std::unique_ptr<Paxlog::tup>& myTup){
	    return (*myTup).executed;
}

void paxserver::execute_arg(const struct execute_arg& ex_arg) {
	LOG(l::DEBUG, id_str() << " Execute Argument" << ex_arg << " state:"<< paxlog.latest_exec() );
	//Another way to check Check if the request is already been taken care of
	/*for (auto it = exec_rid_cache.begin(); it != exec_rid_cache.end(); ++it ){
		std::cout << (*it).first << (*it).second<<std::endl;
		if(((*it).first == ex_arg.nid) && ((*it).second == ex_arg.rid)){
			std::cout << "The request has already been processed" <<std::endl;
			return;
		}
	}*/

	if(primary()){
		if(paxlog.find_rid(ex_arg.nid, ex_arg.rid)){
			LOG(l::DEBUG, id_str() << " find_rid Failed, Probably the request has already been processsed." );
			net->drop(this, ex_arg, "The request has already been processed");
			return;
		}

		std::set<node_id_t> servers = get_other_servers(vc_state.view);
		//Generate a new View timestamp for the request 
		//viewstamp_t new_vs= paxlog.latest_accept(); //Not using this because this seems to be made for use with view change
		viewstamp_t new_vs;
		new_vs.vid = vc_state.view.vid;
		new_vs.ts = ts;
		ts += 1 ;
		paxlog.set_latest_accept(new_vs);

		//LOG the request 
		//Adding one server to count of other servers so as to get the count of total servers 
		paxlog.log(ex_arg.nid, ex_arg.rid, new_vs, ex_arg.request, servers.size() + 1 , net->now()); 
		//Send for Voting to every replica
		for(const auto& serv : servers){
			auto new_rep_arg = std::make_unique<struct replicate_arg>(new_vs, ex_arg, paxlog.latest_exec());
			net->send(this, serv, std::move(new_rep_arg));
		}
		LOG(l::DEBUG, id_str() << " Logged and sent for Vote for Request:" << ex_arg.request );
	}else{
		//Send execute_fail to the client so that it can send request to the correct Primary
		auto new_execute_fail = std::make_unique<struct execute_fail>(vc_state.view.vid, vc_state.view.primary, ex_arg.rid);
		net->send(this, ex_arg.nid, std::move(new_execute_fail));
	}
   //MASSERT(0, "execute_arg not implemented\n");
}

void paxserver::replicate_arg(const struct replicate_arg& repl_arg) {
	//1. Try and execute the operations untill the committed in the message and update lastest_seen 
	//2. Reply with the Viewstamp
	LOG(l::DEBUG, id_str() << id_str() << " Replicate Argument" << repl_arg << " State:"<< paxlog.latest_exec() );
	if(!primary()) {
		//Execute all the Operatins the Replica Can
	    for(auto it = paxlog.begin(); it != paxlog.end(); ++it) {
			//We need to make sure that the View Id is same therefore the comparison has been performed between the 
			//ViewStamps and not just the timestamps
			if((paxlog.latest_exec() <= repl_arg.committed) && paxlog.next_to_exec(it)){
				paxlog.execute(*it);
				std::string result = paxop_on_paxobj(*it);
				vc_state.latest_seen.ts += 1;
				//So that every request which can be executed is executed..
				it = paxlog.begin();
				if(paxlog.latest_accept() <= repl_arg.committed)
					paxlog.set_latest_accept(repl_arg.committed);
				LOG(l::DEBUG, id_str() << " Executed:" << paxlog.latest_exec() << " result:" << result);
			}
		}
		paxlog.trim_front(my_trim_func);

		//Not needed because the inc_resp at the primary is going to take care of incrementing it only for the valid vs. 
		//if(vc_state.latest_seen < repl_arg.vs) {
		int total_server_count = get_serv_cnt(vc_state.view);//(get_other_servers(vc_state.view)).size() + 1;
		paxlog.log(repl_arg.arg.nid, repl_arg.arg.rid, repl_arg.vs, repl_arg.arg.request, total_server_count, net->now());
		//First log then send ACK 
		auto new_rep_res = std::make_unique<struct replicate_res>(repl_arg.vs);
		net->send(this, vc_state.view.primary, std::move(new_rep_res)); 
		LOG(l::DEBUG, id_str() << " Logged and Ack the Request from Primary" );
	}
}


void paxserver::replicate_res(const struct replicate_res& repl_res) {
	//1. Log the respone only primary should be getting these messages.
	//2. When the count of the response is more than half the server count Send Accept_arg message to all
	LOG(l::DEBUG, id_str() << " Replicate response" << repl_res << " State:" << paxlog.latest_exec());
	if(primary()) {
		if(!paxlog.incr_resp(repl_res.vs)){
			LOG(l::DEBUG, id_str() << " Got request for already executed request and then truncated from log" );
			return;
		}
								      
		for(auto it = paxlog.begin(); it != paxlog.end(); ++it) {
			if(((*it)->resp_cnt > (*it)->serv_cnt/2 ) && paxlog.next_to_exec(it) ) {
				paxlog.execute(*it);
				std::string result = paxop_on_paxobj(*it);
				vc_state.latest_seen.ts += 1;
				LOG(l::DEBUG, id_str() << " Executed:" << paxlog.latest_exec() << " result:" << result);
				//Respond to the client
				auto new_exe_succ = std::make_unique<struct execute_success>(result, (*it)->rid);
				net->send(this, (*it)->src, std::move(new_exe_succ));          
				//send Accept arg msgs to The rest of the servers 
				std::set<node_id_t> servers = get_other_servers(vc_state.view);
				for(const auto& server:servers) {		
					auto new_acc_arg = std::make_unique<struct accept_arg>(repl_res.vs);
					net->send(this, server, std::move(new_acc_arg)); 	
				}
			}
		}
		paxlog.trim_front(my_trim_func);
	}
   //MASSERT(0, "replicate_res not implemented\n");
}

void paxserver::accept_arg(const struct accept_arg& acc_arg) {
	LOG(l::DEBUG, id_str() <<" Accept response" << acc_arg << " latest_exec:"<<  paxlog.latest_exec() );	

	for(auto it = paxlog.begin(); it != paxlog.end(); ++it) {
		//if((paxlog.latest_exec() <= acc_arg.committed) && paxlog.next_to_exec(it)){
		if(paxlog.next_to_exec(it)){
			paxlog.execute(*it);
			std::string result = paxop_on_paxobj(*it);
			vc_state.latest_seen.ts += 1;
			LOG(l::DEBUG, id_str() << " Executed:" << paxlog.latest_exec() << " result:" << result);
			//it = paxlog.begin();
		}
	}
	paxlog.trim_front(my_trim_func);
  // MASSERT(0, "accept_arg not implemented\n");
}

