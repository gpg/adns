/**/

static void autosys(adns_state ads, struct timeval now) {
  if (ads->iflags & adns_if_noautosys) return;
  adns_callback(ads,-1,0,0,0);
}

static int callb_checkfd(int maxfd, const fd_set *fds, int fd) {
  return maxfd<0 || !fds ? 1 :
         fd<maxfd && FD_ISSET(fd,fds);
}

int adns_callback(adns_state ads, int maxfd,
		  const fd_set *readfds, const fd_set *writefds,
		  const fd_set *exceptfds) {
  int skip, dgramlen, count;
  enum adns__tcpstate oldtcpstate;

  count= 0;
  oldtcpstate= ads->tcpstate;
  
  if (ads->tcpstate == server_connecting) {
    if (callb_checkfd(maxfd,writefds,ads->tcpsocket)) {
      count++;
      assert(ads->tcprecv.used==0);
      vbuf_ensure(&ads->tcprecv,1);
      if (ads->tcprecv.buf) {
	r= read(ads->tcpsocket,&ads->tcprecv.buf,1);
	if (r==0 || (r<0 && (errno==EAGAIN || errno==EWOULDBLOCK))) {
	  diag("nameserver %s TCP connection made",
	       inet_ntoa(ads->servers[ads->tcpserver].addr));
	  ads->tcpstate= server_connected;
	} else if (r>0) {
	  tcpserver_broken(ads,"connect/read","sent data before first request");
	} else if (errno!=EINTR) {
	  tcpserver_broken(ads,"connect",strerror(errno));
	}
      }
    }
  }
  if (ads->tcpstate == server_connected) {
    if (oldtcpstate == server_connected)
      count+= callb_checkfd(maxfd,readfds,ads->tcpsocket) +
	      callb_checkfd(maxfd,exceptfds,ads->tcpsocket) +
	(ads->tcpsend.used && callb_checkfd(maxfd,writefds,ads->tcpsocket));
    if (oldtcpstate != server_connected || callb_checkfd(maxfd,readfds,ads->tcpsocket)) {
      skip= 0;
      for (;;) {
	if (ads->tcprecv.used<skip+2) {
	  want= 2;
	} else {
	  dgramlen= (ads->tcprecv.buf[skip]<<8) | ads->tcprecv.buf[skip+1];
	  if (ads->tcprecv.used<skip+2+dgramlen) {
	    want= 2+dgramlen;
	  } else {
	    procdgram(ads,ads->tcprecv.buf+skip+2,dgramlen,-1);
	    skip+= 2+dgramlen; continue;
	  }
	}
	Ads->tcprecv.used -= skip;
	memmove(ads->tcprecv.buf,ads->tcprecv.buf+skip,ads->tcprecv.used);
	vbuf_ensure(&ads->tcprecv,want);
	if (ads->tcprecv.used >= ads->tcprecv.avail) break;
	r= read(ads->tcpsocket,
		ads->tcprecv.buf+ads->tcprecv.used,
		ads->tcprecv.avail-ads->tcprecv.used);
	if (r>0) {
	  ads->tcprecv.used+= r;
	} else {
	  if (r<0) {
	    if (errno==EAGAIN || errno==EWOULDBLOCK || errno==ENOMEM) break;
	    if (errno==EINTR) continue;
	  }
	  tcpserver_broken(ads->tcpserver,"read",r?strerror(errno):"closed");
	  break;
	}
      }
    } else if (callb_checkfd(maxfd,exceptfds,ads->tcpsocket)) {
      tcpserver_broken(ads->tcpserver,"select","exceptional condition detected");
    } else if (ads->tcpsend.used && callb_checkfd(maxfd,writefds,ads->tcpsocket)) {
      r= write(ads->tcpsocket,ads->tcpsend.buf,ads->tcpsend.used);
      if (r<0) {
	if (errno!=EAGAIN && errno!=EWOULDBLOCK && errno!=ENOMEM && errno!=EINTR) {
	  tcpserver_broken(ads->tcpserver,"write",strerror(errno));
	}
      } else if (r>0) {
	ads->tcpsend.used -= r;
	memmove(ads->tcpsend.buf,ads->tcpsend.buf+r,ads->tcpsend.used);
      }
    }
  }

  if (
    break;
	
      
	}
	  
  tcpserver_broken(
		
	    if (ads-
	  used= 0;
	  for (;;) {
	  vbuf_ensure(&ads->tcprecv,2);
	  vbuf_ensure(&ads->tcprecv,
	  if (ads->tcprecv.avail<2) break;
      if (ads->tcprecv.used
      
      if (ads->tcprecv.used<2 && ads->tcprecv.avail
      if (ads->tcprecv.used<2 && ads->tcprecv.avail
      r= read(ads->tcpsocket,
      if (adns->tcprecv.used<2) {
	if (
	  
  if (ads->tcpstate != server_disc) {
    
      
    }
  if (maxfd<0 || !readfds || (FD_ISSET
      ads->
      
  abort(); /* FIXME */
}
	  diag("nameserver #%d (%s) TCP connection died: %s",
	       inet_ntoa(ads->servers[tcpserver].addr),

static void inter_maxto(struct timeval **tv_io, struct timeval *tvbuf,
			struct timeval maxto) {
  struct timeval rbuf;

  rbuf= *tv_io;
  if (!rbuf) { *tvbuf= maxto; *tv_io= tvbuf; return; }
  if (timercmp(rbuf,&maxto,>)) *rbuf= maxto;
}

static void inter_maxtoabs(struct timeval **tv_io, struct timeval *tvbuf,
			   struct timeval now, struct timeval maxtime) {
  ldiv_t dr;
  
  maxtime.tv_sec -= (now.tv_sec-1);
  maxtime.tv_usec += (1000-now.tv_usec);
  dr= ldiv(maxtime.tv_usec,1000);
  maxtime.tv_sec += dr.quot;
  maxtime.tv_usec -= dr.rem;
  inter_maxto(tv_io,tvbuf,maxtime);
}

static void localresourcerr(struct timeval **tv_io, struct timeval *tvbuf,
			    const char *syscall) {
  struct timeval tvto_lr;
  
  diag(ads,"local system resources scarce (during %s): %s",syscall,strerror(errno));
  timerclear(&tvto_lr); timevaladd(&tvto_lr,LOCALRESOURCEMS);
  inter_maxto(tv_io, tvbuf, tvto_lr);
  return;
}

static void inter_addfd(int *maxfd, fd_set *fds, int fd) {
  if (fd>=*maxfd) *maxfd= fd+1;
  FD_SET(fd,fds);
}

void adns_interest(adns_state ads, int *maxfd,
		   fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
		   struct timeval **tv_io, struct timeval *tvbuf) {
  struct timeval now;
  adns_query qu;
  int r;
  
  r= gettimeofday(&now,0);
  if (r) { localresourcerr(tv_io,tvbuf,"gettimeofday"); return; }

  for (qu= ads->timew; qu; qu= nqu) {
    nqu= qu->next;
    if (timercmp(&now,qu->timeout,>)) {
      DLIST_UNLINK(ads->timew,qu);
      if (qu->nextudpserver == -1) {
	query_fail(ads,qu,adns_s_notresponding);
      } else {
	DLIST_LINKTAIL(ads->tosend,qu);
      }
    } else {
      inter_maxtoabs(tv_io,tvbuf,now,qu->timeout);
    }
  }
  
  for (qu= ads->tosend; qu; qu= nqu) {
    nqu= qu->next;
    quproc_tosend(ads,qu,now);
  }

  inter_addfd(maxfd,readfds,ads->udpsocket);
  switch (ads->tcpstate) {
  case server_disc:
    break;
  case server_connecting:
    inter_addfd(maxfd,writefds,ads->tcpsocket);
    break;
  case server_connected:
    inter_addfd(maxfd,readfds,ads->tcpsocket);
    inter_addfd(maxfd,exceptfds,ads->tcpsocket);
    if (ads->opbufused) inter_addfd(maxfd,writefds,ads->tcpsocket);
  default:
    abort();
  }
  
}

static int internal_check(adns_state ads,
			  adns_query *query_io,
			  adns_answer **answer,
			  void **context_r) {
  adns_query qu;

  qu= *query_io;
  if (!qu) {
    if (!ads->output.head) return EWOULDBLOCK;
    qu= ads->output.head;
  } else {
    if (qu->id>=0) return EWOULDBLOCK;
  }
  LIST_UNLINK(ads->output,qu);
  *answer= qu->answer;
  if (context_r) *context_r= qu->context;
  free(qu);
  return 0;
}

int adns_wait(adns_state ads,
	      adns_query *query_io,
	      adns_answer **answer_r,
	      void **context_r) {
  int r, maxfd, rsel, rcb;
  fd_set readfds, writefds, exceptfds;
  struct timeval tvbuf, *tvp;
  
  for (;;) {
    r= internal_check(ads,query_io,answer_r,context_r);
    if (r && r != EWOULDBLOCK) return r;
    FD_ZERO(&readfds); FD_ZERO(&writefds); FD_ZERO(&exceptfds);
    maxfd= 0; tvp= 0;
    adns_interest(ads,&maxfd,&readfds,&writefds,&exceptfds,&tvp,&tvbuf);
    rsel= select(maxfd,&readfds,&writefds,&exceptfds,tvp);
    if (rsel==-1) return r;
    rcb= adns_callback(ads,maxfd,&readfds,&writefds,&exceptfds);
    assert(rcb==rsel);
  }
}

int adns_check(adns_state ads,
	       adns_query *query_io,
	       adns_answer **answer_r,
	       void **context_r) {
  autosys(ads);
  return internal_check(ads,query_io,answer_r,context_r);
}
