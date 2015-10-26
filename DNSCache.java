import java.io.*;
import java.net.*;
import java.util.Scanner;
import java.util.ArrayList;
import java.util.HashMap<K,V>

/********************************************************************************
* CIS 457
* Project 2
* DNS Cache
*
*
* @author Jonathan Powers, Brett Greenman, Kevin Anderson
* @version Fall 2015
********************************************************************************/

class DNSCache {
    HashMap<String,String> completeDomainCache;
    //  HashMap<String,String[]> subDomainCache = new HashMap<String,String[]>;

    public DNSCache(){
	completeDomainCache = new HashMap<String,String>;
    }
    public String getIP(String domain){
	return completeDomain.get(domain);
    }

    public appendComplete(String domain, String ip){
	
    }	



    public boolean checkCompleteDomain(String s){
	//NEED TO ADD CHECK FOR TTL
	return completeDomainCache.containsKey(s); //tells whether or not complete name is stored in cache
    }

    public boolean checkSubDomain(String s){

    }
}
