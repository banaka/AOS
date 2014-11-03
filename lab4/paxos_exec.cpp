// Basic routines for Paxos implementation

#include "make_unique.h"
#include "paxmsg.h"
#include "paxserver.h"
#include "log.h"

void paxserver::execute_arg(const struct execute_arg& ex_arg) {
	std::cout << id_str() << " Execute Argument" << ex_arg << " Vc_sate"<< vc_state <<std::endl;
	//Another way to check Check if the request is already been taken care of
	/*for (auto it = exec_rid_cache.begin(); it != exec_rid_cache.end(); ++it ){
		std::cout << (*it).first << (*it).second<<std::endl;
		if(((*it).first == ex_arg.nid) && ((*it).second == ex_arg.rid)){
			std::cout << "The request has already been processed" <<std::endl;
			return;
		}
	}*/

	if(paxlog.find_rid(ex_arg.nid, ex_arg.rid)){
		std::cout << id_str()<<" The request has already been processed" <<std::endl;
		//TODO Check if Generate Execute Success msg Needs to be sent to the client
		return;
	}

	if(primary()){ 
		std::set<node_id_t> servers = get_other_servers(vc_state.view);
		//Generate a new time stamp for this request 
		viewstamp_t new_vs= paxlog.latest_accept();
		new_vs.ts = new_vs.ts + 1 ;
		paxlog.set_latest_accept(new_vs);

		//std::cout << id_str() <<"  LATEST TIMESTAMP "<<paxlog.latest_accept() <<"\n";
		//Adding one server to count of other servers so as to get the count of total servers 
		paxlog.log(ex_arg.nid, ex_arg.rid, new_vs, ex_arg.request, servers.size() + 1 , net->now()); 
		for(const auto& serv : servers){
			auto new_rep_arg = std::make_unique<struct replicate_arg>(new_vs, ex_arg, vc_state.latest_seen);
			net->send(this, serv, std::move(new_rep_arg));
			//LOG(l::DBG_EV, id_str() << " Repicate Argv msg sent:" << net->now()
			//                        << " recent send: " << recent_send[serv]
			//						<< " nid:" << serv << "\n");
		}

		return;
	}else{
		//Send execute Fail to the client
		auto new_execute_fail = std::make_unique<struct execute_fail>(vc_state.view.vid, vc_state.view.primary, ex_arg.rid);
		net->send(this, ex_arg.nid, std::move(new_execute_fail));
	}
   //MASSERT(0, "execute_arg not implemented\n");
}

void paxserver::replicate_arg(const struct replicate_arg& repl_arg) {
	//1. Try and execute the operations untill the committed in the message and update your lastest_seen 
	//2. Check if the view stamp is the geatest Viewstamp seen untill now
	//2. If yes then reply with repl_res message with the vs provided in the repl_arg 
	std::cout << id_str() << " Replicate Argument" << repl_arg << std::endl;

	if(!primary()) {
		//Execute all the Operatins the server can
	    for(auto it = paxlog.begin(); it != paxlog.end(); ++it) {
			//We need to make sure that the View Id is same therefore the comparison has been performed between the 
			//ViewStamps and not just the timestamps. However this would only comes to play when the view changes happens 
			if((vc_state.latest_seen <= repl_arg.committed) && ((*it)->vs > vc_state.latest_seen )){
				paxlog.execute(*it);
			}
		}
		vc_state.latest_seen = repl_arg.committed;

		if(vc_state.latest_seen < repl_arg.vs) {
			int total_server_count = get_serv_cnt(vc_state.view);//(get_other_servers(vc_state.view)).size() + 1;
			paxlog.log(repl_arg.arg.nid, repl_arg.arg.rid, repl_arg.vs, repl_arg.arg.request, total_server_count, net->now());
			//First log then send ACK 
			auto new_rep_res = std::make_unique<struct replicate_res>(repl_arg.vs);
			net->send(this, vc_state.view.primary, std::move(new_rep_res)); 
			//TODO ADD LOG MSG
		}
	}
}

void paxserver::replicate_res(const struct replicate_res& repl_res) {
	//1. Log the respone only primary should be getting these messages.
	//2. When the count of the response is more than half the server count Send Accept_arg message to all
	
	std::cout << id_str() << " Replicate response" << repl_res << std::endl;
	if(primary()) {
		//update the log.
		if(!paxlog.incr_resp(repl_res.vs)){
			std::cout << "Got request for already executed and then truncated from log" << std::endl;
			return;
		}
								      
		for(auto it = paxlog.begin(); it != paxlog.end(); ++it) {
			if(((*it)->vs == repl_res.vs) && ((*it)->resp_cnt > (*it)->serv_cnt/2 ) && !(*it)->executed) {
				paxlog.execute(*it);
				std::string result = paxop_on_paxobj(*it);
				std::cout<< result <<"\n"; 
				vc_state.latest_seen.ts += 1;
				//Respond to the client
				auto new_exe_succ = std::make_unique<struct execute_success>(result, (*it)->rid);
				net->send(this, (*it)->src, std::move(new_exe_succ));          
				//send Accept arg msgs to The rest of the servers 
				std::set<node_id_t> servers = get_other_servers(vc_state.view);
				for(const auto& server:servers) {		
					auto new_acc_arg = std::make_unique<struct accept_arg>(repl_res.vs);
					net->send(this, server, std::move(new_acc_arg)); 	
				}
				break;
			}
		}
	}
   //MASSERT(0, "replicate_res not implemented\n");
}

void paxserver::accept_arg(const struct accept_arg& acc_arg) {
	//Recieved Response from more than half send this msg to every 
	//Generate a string and send to replicate 
	//Find the tuple and if it is not there then add it to the paxlog 

	std::cout << id_str() <<" Accept response" << acc_arg << std::endl;	
	for(auto it = paxlog.begin(); it != paxlog.end(); ++it) {
		if(((*it)->vs == acc_arg.committed) && (!(*it)->executed )) {
			paxlog.execute(*it);
			//std::string result = paxop_on_paxobj(*it);
			break;
		}
	}
	
  // MASSERT(0, "accept_arg not implemented\n");
}
