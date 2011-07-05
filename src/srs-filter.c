#include <errno.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <pthread.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>

#include "srs2.h"
#include "spf2/spf.h"
#include "libmilter/mfapi.h"


#define SRS_MILTER_NAME "srs-milter"
#define SRS_MILTER_VERSION "0.0.1"

#define SS_STATE_NULL             0x00
#define SS_STATE_INVALID_CONN     0x01
#define SS_STATE_INVALID_MSG      0x02

/* Global variables */
static int connections;
/* these should be read from command line or config file */
static int CONFIG_forward = 0;
static int CONFIG_reverse = 0;
static char *CONFIG_socket = NULL;
static char *CONFIG_recip_orig_header = NULL;
static char **CONFIG_local_mail_domains = NULL;
static char *CONFIG_local_auth_domain = NULL;
static char *CONFIG_spf_heloname = NULL;
static union {
   struct sockaddr_in in;
   struct sockaddr_in6 in6;
} CONFIG_spf_address;
static char **CONFIG_srs_secrets = NULL;
static int CONFIG_srs_alwaysrewrite = 0;
static int CONFIG_srs_hashlength = 0;
static int CONFIG_srs_hashmin = 0;
static int CONFIG_srs_maxage = 0;
static char CONFIG_srs_separator = 0;


/* Per-connection data structure. */
struct srs_milter_data {
  int connection_num;
  int state;
  char* sender;
  char** envfromargv;
  char** recip;
  char *recip_orig;
  int recip_remote;
  srs_t *srs;
};


int is_local_addr(const char *addr) {
  int i;
  const char *dom;

  if (!addr)
    return 0;

  if (!CONFIG_local_mail_domains)
    return 0;

  dom  = strrchr(addr, '@')+1;
  if (!dom)
    dom = addr;

  for (i = 0; CONFIG_local_mail_domains[i]; i++) {

    if (strcasecmp(dom, CONFIG_local_mail_domains[i]) == 0) // exact domain name match
      return 1;

    if (strlen(dom) <= strlen(CONFIG_local_mail_domains[i]))
      continue;

    if (strcasecmp(dom+strlen(dom)-strlen(CONFIG_local_mail_domains[i]), CONFIG_local_mail_domains[i]) == 0) // match subdomain
      return 1;
  }

  return 0;
}



// https://www.milter.org/developers/api/xxfi_connect
static sfsistat
xxfi_srs_milter_connect(SMFICTX* ctx, char *hostname, _SOCK_ADDR *hostaddr) {
  struct srs_milter_data* cd;

  cd = (struct srs_milter_data*) malloc(sizeof(struct srs_milter_data));
  if (!cd) {
    syslog(LOG_DEBUG, "conn# ?[?] - xxfi_srs_milter_connect(\"%s\", %p): can't allocate memory",
           hostname, hostaddr);
    return SMFIS_TEMPFAIL;
  }
  if (smfi_setpriv(ctx, (void*) cd) != MI_SUCCESS) {
    syslog(LOG_DEBUG, "conn# ?[?] - xxfi_srs_milter_connect(\"%s\", %p): can't set ctx data",
           hostname, hostaddr);
    return SMFIS_TEMPFAIL;
  }

  bzero(cd, sizeof(struct srs_milter_data));
  cd->state = SS_STATE_NULL;
  cd->connection_num = ++connections; // this should be done in thread-safe way

  syslog(LOG_DEBUG, "conn# %d[%i] - xxfi_srs_milter_connect(\"%s\", hostaddr)",
         cd->connection_num, cd->state, hostname);

  return SMFIS_CONTINUE;
}



// https://www.milter.org/developers/api/xxfi_envfrom
static sfsistat
xxfi_srs_milter_envfrom(SMFICTX* ctx, char** argv) {
  struct srs_milter_data* cd = (struct srs_milter_data*) smfi_getpriv(ctx);

  if (cd->state & SS_STATE_INVALID_CONN)
    return SMFIS_CONTINUE;

  syslog(LOG_DEBUG, "conn# %d[%i] - xxfi_srs_milter_envfrom(\"%s\")",
         cd->connection_num, cd->state, argv[0]);

  if (strlen(argv[0]) < 1 || strcmp(argv[0], "<>") == 0 || argv[0][0] != '<' || argv[0][strlen(argv[0])-1] != '>' || !strchr(argv[0], '@')) {
    cd->state |= SS_STATE_INVALID_MSG;
    syslog(LOG_DEBUG, "conn# %d[%i] - xxfi_srs_milter_envfrom(\"%s\"): skipping \"MAIL FROM: %s\"",
           cd->connection_num, cd->state, argv[0], argv[0]);
    return SMFIS_CONTINUE;
  }

  // cleanup data structure for new message
  // (there can be more messages send throught one connection,
  // so this structure could be filled by previous message)
  cd->state = SS_STATE_NULL;

  if (cd->sender) {
    free(cd->sender);
    cd->sender = NULL;
  }

  if (cd->envfromargv) {
    int i;
    for (i = 0; cd->envfromargv[i]; i++)
      free(cd->envfromargv[i]);
    free(cd->envfromargv);
    cd->envfromargv = NULL;
  }

  if (cd->recip) {
    int i;
    for (i = 0; cd->recip[i]; i++)
      free(cd->recip[i]);
    free(cd->recip);
    cd->recip = NULL;
  }

  if (cd->recip_orig) {
    free(cd->recip_orig);
    cd->recip_orig = NULL;
  }

  cd->recip_remote = 0;

  // strore MAIL FROM: address
  cd->sender = (char *) malloc(strlen(argv[0])-1);
  if (!cd->sender) {
    // memory allocation problem
    cd->state |= SS_STATE_INVALID_MSG;
    return SMFIS_CONTINUE;
  }
  strncpy(cd->sender, argv[0]+1, strlen(argv[0])-2);
  cd->sender[strlen(argv[0])-1] = '\0';

  // store MAIL FROM: arguments
  {
    int argc = 0;
    while (argv[argc]) argc++;
    cd->envfromargv = (char **) malloc((argc+1)*sizeof(char *));
    for (argc = 0; argv[argc]; argc++) {
      cd->envfromargv[argc] = strdup(argv[argc]);
      if (!cd->envfromargv[argc]) {
        // memory allocation problem
        cd->state |= SS_STATE_INVALID_MSG;
        return SMFIS_CONTINUE;
      }
    }
    cd->envfromargv[argc] = NULL;
  }

  return SMFIS_CONTINUE;
}



// https://www.milter.org/developers/api/xxfi_envrcpt
static sfsistat
xxfi_srs_milter_envrcpt(SMFICTX* ctx, char** argv) {
  struct srs_milter_data* cd = (struct srs_milter_data*) smfi_getpriv(ctx);

  if (cd->state & SS_STATE_INVALID_CONN)
    return SMFIS_CONTINUE;

  syslog(LOG_DEBUG, "conn# %d[%i] - xxfi_srs_milter_envrcpt(\"%s\")",
         cd->connection_num, cd->state, argv[0]);

  // get recipient address
  char *recip = (char *) malloc(strlen(argv[0])-1);
  if (!recip) {
    // memory allocation problem
    cd->state |= SS_STATE_INVALID_MSG;
    return SMFIS_CONTINUE;
  }
  strncpy(recip, argv[0]+1, strlen(argv[0])-2);
  recip[strlen(argv[0])-1] = '\0';

  if (!is_local_addr(recip)) {
    cd->recip_remote = 1;
  } else {
    // list of local SRS recipient addresses that should be reversed
    if (SRS_IS_SRS_ADDRESS(recip)) {
      int argc = 0;

      if (!cd->recip) {
        cd->recip = (char **) malloc((argc+2)*sizeof(char *));
      } else {
        while (argv[argc]) argc++;
        cd->recip = (char **) realloc(cd->recip, (argc+2)*sizeof(char *));
      }

      if (!cd->recip) {
        // memory allocation problem
        cd->state |= SS_STATE_INVALID_MSG;
      } else {
        cd->recip[argc] = strdup(argv[0]);
        cd->recip[argc+1] = NULL;
        if (!cd->recip[argc]) {
          // memory allocation problem
          cd->state |= SS_STATE_INVALID_MSG;
        }
      }
    }
  }

  free(recip);

  return SMFIS_CONTINUE;
}



// https://www.milter.org/developers/api/xxfi_header
static sfsistat
xxfi_srs_milter_header(SMFICTX* ctx, char *headerf, char *headerv) {
  struct srs_milter_data* cd = (struct srs_milter_data*) smfi_getpriv(ctx);

  if (cd->state & (SS_STATE_INVALID_CONN | SS_STATE_INVALID_MSG))
    return SMFIS_CONTINUE;

  if (!CONFIG_reverse)
    return SMFIS_CONTINUE;

  syslog(LOG_DEBUG, "conn# %d[%i] - xxfi_srs_milter_header(\"%s\", \"%s\")",
         cd->connection_num, cd->state, headerf, headerv);

  // Search for header with original recipient.
  // This header should be added by some content filter
  // for all incomming mail (e.g. by modified amavis used
  // as post-queue content filter).
  if (CONFIG_recip_orig_header && strcasecmp(headerf, CONFIG_recip_orig_header) == 0 && is_local_addr(headerv)) {

    if (!cd->recip_orig) {
      cd->recip_orig = strdup(headerv);
      if (cd->recip_orig) {
        // memory allocation problem
        cd->state |= SS_STATE_INVALID_MSG;
        return SMFIS_CONTINUE;
      }

    } else {
      // TODO: normalize header value before comparison
      if (strcasecmp(headerv, cd->recip_orig) != 0)
        syslog(LOG_WARNING, "conn# %d[%i] - xxfi_srs_milter_header(\"%s\", \"%s\"): duplicate %s to %s",
               cd->connection_num, cd->state, headerf, headerv,
               CONFIG_recip_orig_header, cd->recip_orig);
    }
  }

  return SMFIS_CONTINUE;
}



// https://www.milter.org/developers/api/xxfi_eom
static sfsistat
xxfi_srs_milter_eom(SMFICTX* ctx) {
  struct srs_milter_data* cd = (struct srs_milter_data*) smfi_getpriv(ctx);

  if (cd->state & (SS_STATE_INVALID_CONN | SS_STATE_INVALID_MSG))
    return SMFIS_CONTINUE;

  char *queue_id = smfi_getsymval(ctx, "{i}");
  if (!queue_id) queue_id = "unknown";

  syslog(LOG_DEBUG, "conn# %d[%i][%s] - xxfi_srs_milter_eom()", cd->connection_num, cd->state, queue_id);

  int fix_envfrom = 0;

  // non-local sender to non-local recipient
  // SPF can prevent forwarding, check if it is the case
  // for this particular sender domain
  if (CONFIG_forward && !is_local_addr(cd->sender) && cd->recip_remote) {
    SPF_server_t *spf_server = NULL;
    SPF_response_t *spf_response = NULL;
    SPF_request_t *spf_request = NULL;
    SPF_errcode_t spf_ret = SPF_E_SUCCESS;
    char host[INET_ADDRSTRLEN+1];

    // check if non-local MAIL FROM: sender domain has SPF data in DNS
    if ((spf_server = SPF_server_new(SPF_DNS_RESOLV, 0))) {
//      char *site;
//      if ((site = smfi_getsymval(ctx, "j")))
//        SPF_server_set_rec_dom(spf_server, site);
//      else
//        SPF_server_set_rec_dom(spf_server, "localhost");
      if ((spf_request = SPF_request_new(spf_server))) {
        if (CONFIG_spf_address.in.sin_family == AF_INET) {
          SPF_request_set_ipv4(spf_request, CONFIG_spf_address.in.sin_addr);
          inet_ntop(AF_INET, &CONFIG_spf_address.in.sin_addr, host, sizeof(host));
        } else {
          SPF_request_set_ipv6(spf_request, CONFIG_spf_address.in6.sin6_addr);
          inet_ntop(AF_INET6, &CONFIG_spf_address.in6.sin6_addr, host, sizeof(host));
        }
        while (1) {
          spf_ret = SPF_request_set_helo_dom(spf_request, CONFIG_spf_heloname);
          if (spf_ret != SPF_E_SUCCESS) break;
          spf_ret = SPF_request_set_env_from(spf_request, cd->sender);
          if (spf_ret != SPF_E_SUCCESS) break;
          spf_ret = SPF_request_query_mailfrom(spf_request, &spf_response);
          if (spf_ret != SPF_E_SUCCESS) break;

          if (spf_response) {
            SPF_result_t spf_result = SPF_response_result(spf_response);
            syslog(LOG_DEBUG, "conn# %d[%i][%s] - xxfi_srs_milter_eom(): spf(%s, %s, %s) = %i (%s)",
                   cd->connection_num, cd->state, queue_id, host, CONFIG_spf_heloname,
                   cd->sender, spf_ret, SPF_strresult(spf_ret));
            // TODO: make this configurable
            // (I'm not sure if SRS "MAIL FROM:" sender adress format can
            // cause some problems/mail rejection, so right now I'm taking
            // conservative approach for SRS "MAIL FROM:" rewriting)
            //if (!(status == SPF_RESULT_PASS || status == SPF_RESULT_NEUTRAL))
            if (spf_result == SPF_RESULT_FAIL || spf_result == SPF_RESULT_SOFTFAIL)
              fix_envfrom = 1;
          }

          break;
        }
        if (spf_ret != SPF_E_SUCCESS) {
          syslog(LOG_NOTICE, "conn# %d[%i][%s] - xxfi_srs_milter_eom(): libspf2 error %i (%s)",
                 cd->connection_num, cd->state, queue_id, spf_ret, SPF_strerror(spf_ret));
        }
      }
    }
  }

  // try to guess mail address from auth name in case we
  // was not able to find original recipient in mail headers
  if (fix_envfrom && CONFIG_local_auth_domain && !cd->recip_orig) {
    char *auth_authen = smfi_getsymval(ctx, "{auth_authen}");
    if (auth_authen) {
      cd->recip_orig = (char *) malloc(strlen(auth_authen) + strlen(CONFIG_local_auth_domain) + 2);
      if (cd->recip_orig) {
        // memory allocation problem
        cd->state |= SS_STATE_INVALID_MSG;
        return SMFIS_CONTINUE;
      }
      sprintf(cd->recip_orig, "%s@%s", auth_authen, CONFIG_local_auth_domain);
    }
  }

  if ((fix_envfrom && cd->recip_orig) || (CONFIG_reverse && cd->recip)) {
    // do some SRS magic...
    int i;

    if (!cd->srs) { // initialize & configure SRS
      cd->srs = srs_new();
      if (!cd->srs) {
        cd->state |= SS_STATE_INVALID_MSG;
        return SMFIS_CONTINUE;
      }

      if (CONFIG_srs_alwaysrewrite > 0)
        srs_set_alwaysrewrite(cd->srs, CONFIG_srs_alwaysrewrite);
      if (CONFIG_srs_hashlength > 0)
        srs_set_hashlength(cd->srs, CONFIG_srs_hashlength);
      if (CONFIG_srs_hashmin > 0)
        srs_set_hashmin(cd->srs, CONFIG_srs_hashmin);
      if (CONFIG_srs_maxage > 0)
        srs_set_maxage(cd->srs, CONFIG_srs_maxage);
      if (CONFIG_srs_separator != 0)
        srs_set_separator(cd->srs, CONFIG_srs_separator);
      for (i = 0; CONFIG_srs_secrets && CONFIG_srs_secrets[i]; i++)
        srs_add_secret(cd->srs, CONFIG_srs_secrets[i]);
    }

    int srs_res;
    char *out = NULL;
    char *queue_id = smfi_getsymval(ctx, "{i}");

    if (fix_envfrom && cd->recip_orig) {
      // modify MAIL FROM: address to SRS format
      if ((srs_res = srs_forward_alloc(cd->srs, &out, cd->sender, cd->recip_orig)) == SRS_SUCCESS) {
        if (smfi_chgfrom(ctx, out, NULL) != MI_SUCCESS) {
          syslog(LOG_ERR, "conn# %d[%i][%s] - xxfi_srs_milter_eom(): smfi_chgfrom(ctx, %s, NULL) failed",
                 cd->connection_num, cd->state, queue_id, out);
        } else {
          syslog(LOG_DEBUG, "conn# %d[%i][%s] - xxfi_srs_milter_eom(): smfi_chgfrom(ctx, %s, NULL) OK",
                 cd->connection_num, cd->state, queue_id, out);
        }
      } else {
        syslog(LOG_ERR, "conn# %d[%i][%s] - xxfi_srs_milter_eom(): srs_forward_alloc(srs, out, %s, %s) failed: %i (%s)",
               cd->connection_num, cd->state, queue_id, cd->sender, cd->recip_orig, srs_res, srs_strerror(srs_res));
      }

      if (out)
        free(out);
    }

    if (CONFIG_reverse && cd->recip) {
      // modify RCPT TO: by removing SRS format
      for (i = 0; cd->recip[i]; i++) {
        if ((srs_res = srs_reverse_alloc(cd->srs, &out, cd->recip[i])) == SRS_SUCCESS) {
          if (smfi_delrcpt(ctx, cd->recip[i]) != MI_SUCCESS) {
            syslog(LOG_ERR, "conn# %d[%i][%s] - xxfi_srs_milter_eom(): smfi_delrcpt(ctx, %s) failed",
                   cd->connection_num, cd->state, queue_id, cd->recip[i]);
          } else if (smfi_addrcpt(ctx, out) != MI_SUCCESS) {
            syslog(LOG_ERR, "conn# %d[%i][%s] - xxfi_srs_milter_eom(): smfi_addrcpt(ctx, %s) failed",
                   cd->connection_num, cd->state, queue_id, out);
          } else {
            syslog(LOG_DEBUG, "conn# %d[%i][%s] - xxfi_srs_milter_eom(): smfi_{del,add}rcpt(%s, %s) OK",
                   cd->connection_num, cd->state, queue_id, cd->recip[i], out);
          }
        } else {
          syslog(LOG_ERR, "conn# %d[%i][%s] - xxfi_srs_milter_eom(): srs_reverse_alloc(srs, out, %s) failed: %i (%s)",
                 cd->connection_num, cd->state, queue_id, cd->recip[i], srs_res, srs_strerror(srs_res));
        }

        if (out)
          free(out);
      }
    }
  }

  return SMFIS_CONTINUE;
}



// https://www.milter.org/developers/api/xxfi_close
static sfsistat
xxfi_srs_milter_close(SMFICTX* ctx) {
  struct srs_milter_data* cd = (struct srs_milter_data*) smfi_getpriv(ctx);

  syslog(LOG_DEBUG, "conn# %d[%i] - xxfi_srs_milter_close()", cd->connection_num, cd->state);

  if (cd) {
    int i = 0;

    smfi_setpriv(ctx, NULL);

    if (cd->sender)
      free(cd->sender);

    if (cd->envfromargv) {
      for (i = 0; cd->envfromargv[i]; i++)
        free(cd->envfromargv[i]);
      free(cd->envfromargv);
    }

    if (cd->recip) {
      for (i = 0; cd->recip[i]; i++)
        free(cd->recip[i]);
      free(cd->recip);
    }

    if (cd->recip_orig)
      free(cd->recip_orig);

    if (cd->srs)
      srs_free(cd->srs);

    free(cd);
  }

  return SMFIS_CONTINUE;
}




static struct smfiDesc smfilter = {
  SRS_MILTER_NAME,		/* filter name */
  SMFI_VERSION,			/* version code -- do not change */
  SMFIF_CHGFROM | SMFIF_ADDRCPT | SMFIF_DELRCPT ,	/* flags */
  xxfi_srs_milter_connect,	/* connection info filter */
  NULL,				/* SMTP HELO command filter */
  xxfi_srs_milter_envfrom,	/* envelope sender filter */
  xxfi_srs_milter_envrcpt,	/* envelope recipient filter */
  xxfi_srs_milter_header,	/* header filter */
  NULL,				/* end of header */
  NULL,				/* body block filter */
  xxfi_srs_milter_eom,		/* end of message */
  NULL,				/* message aborted */
  xxfi_srs_milter_close		/* connection cleanup */
};




void daemonize() {
  pid_t pid, sid;

  /* Fork off the parent process */
  pid = fork();
  if (pid < 0) {
    syslog(LOG_ERR, "forking daemon process failed: %s", strerror(errno));
    exit(EXIT_FAILURE);
  }
  /* If we got a good PID, then
     we can exit the parent process. */
  if (pid > 0) {
    syslog(LOG_DEBUG, "exiting parent process");
    exit(EXIT_SUCCESS);
  }

  /* Change the file mode mask */
  umask(0);

  /* Open any logs here */

  /* Create a new SID for the child process */
  sid = setsid();
  if (sid < 0) {
    /* Log any failure here */
    syslog(LOG_DEBUG, "can't create new SID: %s", strerror(errno));
    exit(EXIT_FAILURE);
  }

  /* Change the current working directory */
  if ((chdir("/")) < 0) {
    /* Log any failure here */
    syslog(LOG_DEBUG, "can't chagne working directory: %s", strerror(errno));
    exit(EXIT_FAILURE);
  }

  /* Close out the standard file descriptors */
  close(STDIN_FILENO);
  close(STDOUT_FILENO);
  close(STDERR_FILENO);
}




void usage(char *argv0) {
  fprintf(stderr, "SRS milter (version $Id$)\n");
  fprintf(stderr, "usage:\n");
  fprintf(stderr, "  %s --socket unix:/var/run/srs-milter.sock \\\n", argv0);
  fprintf(stderr, "    --local-recip-header=X-Original-Recipient \\\n");
  fprintf(stderr, "    --local-mail-domain=example.com \\\n");
  fprintf(stderr, "    --local-mail-domain=.allsubdomains.example.com \\\n");
  fprintf(stderr, "    --local-auth-domain=example.com \\\n");
  fprintf(stderr, "    --srs-secret=secret1 --srs-secret=secret2 \\\n");
  fprintf(stderr, "    --debug\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "options:\n");
  fprintf(stderr, "  -h, --help\n");
  fprintf(stderr, "      this help message\n");
  fprintf(stderr, "  -d, --debug\n");
  fprintf(stderr, "      don't daemonize this process\n");
  fprintf(stderr, "  -P, --pidfile\n");
  fprintf(stderr, "      filename where to store process PID\n");
  fprintf(stderr, "  -s, --socket\n");
  fprintf(stderr, "      {unix|local}:/path/to/file -- a named pipe.\n");
  fprintf(stderr, "      inet:port@{hostname|ip-address} -- an IPV4 socket.\n");
  fprintf(stderr, "      inet6:port@{hostname|ip-address} -- an IPV6 socket.\n");
  fprintf(stderr, "  -f, --forward\n");
  fprintf(stderr, "      rewrite MAIL TO: envelope address to SRS for forwarded mail\n");
  fprintf(stderr, "      (non-local sender and recipient + orig_recip in mail header)\n");
  fprintf(stderr, "      (apply this rewriting only on outgoing mails)\n");
  fprintf(stderr, "  -r, --reverse\n");
  fprintf(stderr, "      remove SRS encoding from local RCPT TO: envepope addresses\n");
//  fprintf(stderr, "      (apply this rewriting only on incomming mails)\n");
  fprintf(stderr, "  -p, --local-recip-header\n");
  fprintf(stderr, "      mail header that contain original local recipient address\n");
  fprintf(stderr, "  -m, --local-mail-domain\n");
  fprintf(stderr, "      all local mail domains for that we accept mail\n");
  fprintf(stderr, "  -u, --local-auth-domain\n");
  fprintf(stderr, "      in case of missing header with original local recipient address\n");
  fprintf(stderr, "      we can still build this address for authenticated user using their\n");
  fprintf(stderr, "      username and this parameter (it assumes that each user has valid\n");
  fprintf(stderr, "      mail address username@domain)\n");
  fprintf(stderr, "  -l, --spf-heloname\n");
  fprintf(stderr, "      use this heloname for SPF checks (default: gethostname())\n");
  fprintf(stderr, "  -a, --spf-address\n");
  fprintf(stderr, "      use this address for SPF checks (default: gethostaddr())\n");
  fprintf(stderr, "  -c, --srs-secret\n");
  fprintf(stderr, "      secret string for SRS hashing algorithm\n");
  fprintf(stderr, "  -w, --srs-alwaysrewrite\n");
  fprintf(stderr, "  -g, --srs-hashlength\n");
  fprintf(stderr, "  -i, --srs-hashmin\n");
  fprintf(stderr, "  -x, --srs-maxage\n");
  fprintf(stderr, "  -e, --srs-separator\n");
  fprintf(stderr, "      separator of the SRS address part (you can use '+', '-', '=')\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "example:\n");
  fprintf(stderr, "  %s --forward \\\n", argv0);
  fprintf(stderr, "    --socket=inet:10043@localhost \\\n");
  fprintf(stderr, "    --local-recip-header=X-CTU-FNSPE-Recip \\\n");
  fprintf(stderr, "    --local-mail-domain=.fjfi.cvut.cz \\\n");
  fprintf(stderr, "    --local-mail-domain=.crrc.cvut.cz \\\n");
  fprintf(stderr, "    --local-auth-domain=fjfi.cvut.cz \\\n");
  fprintf(stderr, "    --srs-secret=secret\n");
  fprintf(stderr, "  %s --reverse \\\n", argv0);
  fprintf(stderr, "    --socket=inet:10044@localhost \\\n");
  fprintf(stderr, "    --local-mail-domain=.fjfi.cvut.cz \\\n");
  fprintf(stderr, "    --local-mail-domain=.crrc.cvut.cz \\\n");
  fprintf(stderr, "    --srs-secret=secret\n");
  fprintf(stderr, "\n");
}




int main(int argc, char* argv[]) {
  int c, i;
  int debug_flag = 0;
  char *address = NULL;
  FILE *f;

  while (1) {
    static struct option long_options[] = {
      /* These options set a flag. */
//      {"verbose", no_argument,       &verbose_flag, 1},
//      {"brief",   no_argument,       &verbose_flag, 0},
      /* These options don't set a flag.
         We distinguish them by their indices. */
      {"help",                   no_argument,       0, 'h'},
      {"debug",                  no_argument,       0, 'd'},
      {"pidfile",                required_argument, 0, 'P'},
      {"socket",                 required_argument, 0, 's'},
      {"forward",                no_argument,       0, 'f'},
      {"reverse",                no_argument,       0, 'r'},
      {"local-recip-header",     required_argument, 0, 'p'},
      {"local-mail-domain",      required_argument, 0, 'm'},
      {"local-auth-domain",      required_argument, 0, 'u'},
      {"spf-heloname",           required_argument, 0, 'l'},
      {"spf-address",            required_argument, 0, 'a'},
      {"srs-secret",             required_argument, 0, 'c'},
      {"srs-alwaysrewrite",      no_argument,       0, 'w'},
      {"srs-hashlength",         required_argument, 0, 'g'},
      {"srs-hashmin",            required_argument, 0, 'i'},
      {"srs-maxage",             required_argument, 0, 'x'},
      {"srs-separator",          required_argument, 0, 'e'},
      {0, 0, 0, 0}
    };
    /* getopt_long stores the option index here. */
    int option_index = 0;

    c = getopt_long(argc, argv, "hdP:s:f:r:p:m:a:c:wg:i:x:e:",
                    long_options, &option_index);

    /* Detect the end of the options. */
    if (c == -1)
      break;

    switch (c) {
      case 0:
        /* If this option set a flag, do nothing else now. */
        if (long_options[option_index].flag != 0)
          break;
        printf("option %s", long_options[option_index].name);
        if (optarg)
          printf(" with arg %s", optarg);
        printf("\n");
        break;

      case 'h':
        usage(argv[0]);
        exit(EXIT_SUCCESS);
        break;

      case 'd':
        debug_flag = 1;
        break;

      case 'P':
        f = fopen(optarg, "w");
        fprintf(f, "%i", (int) getpid());
        fclose(f);
        break;

      case 's':
        CONFIG_socket = optarg;
        break;

      case 'f':
        CONFIG_forward = 1;
        break;

      case 'r':
        CONFIG_reverse = 1;
        break;

      case 'p':
        CONFIG_recip_orig_header = optarg;
        break;

      case 'm':
        i = 0;
        if (!CONFIG_local_mail_domains) {
          CONFIG_local_mail_domains = (char **) malloc((i+2)*sizeof(char *));
        } else {
          while (CONFIG_local_mail_domains[i]) i++;
          CONFIG_local_mail_domains = (char **) realloc(CONFIG_local_mail_domains, (i+2)*sizeof(char *));
        }
        CONFIG_local_mail_domains[i] = optarg;
        CONFIG_local_mail_domains[i+1] = NULL;
        break;

      case 'u':
        CONFIG_local_auth_domain = optarg;
        break;

      case 'c':
        i = 0;
        if (!CONFIG_srs_secrets) {
          CONFIG_srs_secrets = (char **) malloc((i+2)*sizeof(char *));
        } else {
          while (CONFIG_srs_secrets[i]) i++;
          CONFIG_srs_secrets = (char **) realloc(CONFIG_srs_secrets, (i+2)*sizeof(char *));
        }
        CONFIG_srs_secrets[i] = optarg;
        CONFIG_srs_secrets[i+1] = NULL;
        break;

      case 'l':
        CONFIG_spf_heloname = optarg;
        break;

      case 'a':
        address = optarg;
        break;

      case 'w':
        CONFIG_srs_alwaysrewrite = 1;
        break;

      case 'g':
        CONFIG_srs_hashlength = atoi(optarg);
        break;

      case 'i':
        CONFIG_srs_hashmin = atoi(optarg);
        break;

      case 'x':
        CONFIG_srs_maxage = atoi(optarg);
        break;

      case 'e':
        CONFIG_srs_separator = optarg[0];
        break;

      case '?':
        /* getopt_long already printed an error message. */
        break;

      default:
        abort ();
    }
  }

  /* Print any remaining command line arguments (not options). */
  if (optind < argc) {
    printf ("non-option ARGV-elements: ");
    while (optind < argc)
      printf ("%s ", argv[optind++]);
    putchar ('\n');
  }

  openlog(SRS_MILTER_NAME, LOG_PID, LOG_MAIL);
  {
    int i;
    char args[1024] = "";
    for (i = 1; i < argc; i++) {
      strncat(args, " ", 1023);
      strncat(args, argv[i], 1023);
    }
    syslog(LOG_NOTICE, "Starting %s v%s (args:%s)", SRS_MILTER_NAME, SRS_MILTER_VERSION, args);
  }

  // print and validate configuration
  {
    // Milter library version
    unsigned int milter_major, milter_minor, milter_patch;
    smfi_version(&milter_major, &milter_minor, &milter_patch);
    syslog(LOG_DEBUG, "MILTER(%i, %i, %i)", milter_major, milter_minor, milter_patch);

    // SPF library version
    int spf_major, spf_minor, spf_patch;
    SPF_get_lib_version(&spf_major, &spf_minor, &spf_patch);
    syslog(LOG_DEBUG, "SPF(%i, %i, %i)", spf_major, spf_minor, spf_patch);

    // SRS library version
    // ???

    // validate configuration
    if (!CONFIG_forward && !CONFIG_reverse) {
      usage(argv[0]);
      fprintf(stderr, "ERROR: use forward or reverse (or both)\n");
      exit(EXIT_FAILURE);
    }

    if (!CONFIG_socket) {
      usage(argv[0]);
      fprintf(stderr, "ERROR: missing socket configuration\n");
      exit(EXIT_FAILURE);
    }

    if (!CONFIG_spf_heloname) {
      CONFIG_spf_heloname = (char *) malloc(64);
      gethostname(CONFIG_spf_heloname, 63);
    }

    if (address) {
      if (inet_pton(AF_INET, address, &CONFIG_spf_address) <= 0)
        if (inet_pton(AF_INET6, address, &CONFIG_spf_address) <= 0) {
          usage(argv[0]);
          fprintf(stderr, "ERROR: invalid SPF address %s\n", address);
          exit(EXIT_FAILURE);
        }
    } else {
      // get local address
      struct ifaddrs *ifAddrStruct = NULL;
      struct ifaddrs *ifa = NULL;

      getifaddrs(&ifAddrStruct);

      for (ifa = ifAddrStruct; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr)
          continue;
        if(ifa->ifa_flags & IFF_LOOPBACK)
          continue;
        if(ifa->ifa_flags & IFF_POINTOPOINT)
          continue;
        if (ifa->ifa_addr->sa_family == AF_INET) { // check it is IP4
          memcpy(&CONFIG_spf_address.in, ifa->ifa_addr, sizeof(struct sockaddr_in));
          break;
//        } else if (ifa->ifa_addr->sa_family == AF_INET6) { // check it is IP6
//          memcpy(&CONFIG_spf_address.in6, ifa->ifa_addr, sizeof(struct sockaddr_in6));
        }
      }

      if (ifAddrStruct!=NULL)
        freeifaddrs(ifAddrStruct);
    }

    if (!CONFIG_srs_secrets || !CONFIG_srs_secrets[0]) {
      usage(argv[0]);
      fprintf(stderr, "ERROR: missing srs-secrets configuration\n");
      exit(EXIT_FAILURE);
    }

    srs_t *srs = srs_new();
    int srs_res = SRS_SUCCESS;

    while (1) {
      if (CONFIG_srs_alwaysrewrite > 0)
        if ((srs_res = srs_set_alwaysrewrite(srs, CONFIG_srs_alwaysrewrite)) != SRS_SUCCESS)
          break;
      if (CONFIG_srs_hashlength > 0)
        if ((srs_res = srs_set_hashlength(srs, CONFIG_srs_hashlength)) != SRS_SUCCESS)
          break;
      if (CONFIG_srs_hashmin > 0)
        if ((srs_res = srs_set_hashmin(srs, CONFIG_srs_hashmin)) != SRS_SUCCESS)
          break;
      if (CONFIG_srs_maxage > 0)
        if ((srs_res = srs_set_maxage(srs, CONFIG_srs_maxage)) != SRS_SUCCESS)
          break;
      if (CONFIG_srs_separator != 0)
        if ((srs_res = srs_set_separator(srs, CONFIG_srs_separator)) != SRS_SUCCESS)
          break;
      for (i = 0; CONFIG_srs_secrets && CONFIG_srs_secrets[i]; i++)
        if ((srs_res = srs_add_secret(srs, CONFIG_srs_secrets[i])) != SRS_SUCCESS)
          break;
      break;
    }
    if (srs_res != SRS_SUCCESS) {
      usage(argv[0]);
      fprintf(stderr, "ERROR: failure while setting SRS configuration: %i (%s)\n", srs_res, srs_strerror(srs_res));
      exit(EXIT_FAILURE);
    }

    srs_free(srs);

    // print configuration
    if (CONFIG_forward)
      syslog(LOG_DEBUG, "config forward: %i", CONFIG_forward);
    if (CONFIG_reverse)
      syslog(LOG_DEBUG, "config reverse: %i", CONFIG_reverse);
    if (CONFIG_socket)
      syslog(LOG_DEBUG, "config socket: %s", CONFIG_socket);
    if (CONFIG_recip_orig_header)
      syslog(LOG_DEBUG, "config recip_orig_header: %s", CONFIG_recip_orig_header);
    for (i = 0; CONFIG_local_mail_domains && CONFIG_local_mail_domains[i]; i++)
      syslog(LOG_DEBUG, "config local_mail_domains: %s", CONFIG_local_mail_domains[i]);
    if (CONFIG_local_auth_domain)
      syslog(LOG_DEBUG, "config local_auth_domain: %s", CONFIG_local_auth_domain);
    if (CONFIG_spf_heloname)
      syslog(LOG_DEBUG, "config spf_heloname: %s", CONFIG_spf_heloname);
    if (CONFIG_spf_address.in.sin_family == AF_INET) {
      char host[INET_ADDRSTRLEN+1];
      inet_ntop(AF_INET, &CONFIG_spf_address.in.sin_addr, host, INET_ADDRSTRLEN);
      syslog(LOG_DEBUG, "config spf_address: %s (IP)", host);
    } else {
      char host[INET_ADDRSTRLEN+1];
      inet_ntop(AF_INET6, &CONFIG_spf_address.in6.sin6_addr, host, INET_ADDRSTRLEN);
      syslog(LOG_DEBUG, "config spf_address: %s (IPv6)", host);
    }
    for (i = 0; CONFIG_srs_secrets && CONFIG_srs_secrets[i]; i++)
      syslog(LOG_DEBUG, "config srs_secrets: %s", CONFIG_srs_secrets[i]);
    if (CONFIG_srs_alwaysrewrite > 0)
      syslog(LOG_DEBUG, "config srs_alwaysrewrite: %i", CONFIG_srs_alwaysrewrite);
    if (CONFIG_srs_hashlength > 0)
      syslog(LOG_DEBUG, "config srs_hashlength: %i", CONFIG_srs_hashlength);
    if (CONFIG_srs_hashmin > 0)
      syslog(LOG_DEBUG, "config srs_hashmin: %i", CONFIG_srs_hashmin);
    if (CONFIG_srs_maxage > 0)
      syslog(LOG_DEBUG, "config srs_maxage: %i", CONFIG_srs_maxage);
    if (CONFIG_srs_separator != 0)
      syslog(LOG_DEBUG, "config srs_separator: %c", CONFIG_srs_separator);

  }

  {
    pid_t ppid = getpid();
    if (!debug_flag) {
      daemonize();
      syslog(LOG_NOTICE, "daemonized PID %i", (int) ppid);
    }
  }

  smfi_setconn(CONFIG_socket);
  if (smfi_register(smfilter) == MI_FAILURE) {
    fprintf(stderr, "%s: register failed\n", SRS_MILTER_NAME);
    exit(EXIT_FAILURE);
  }
  if (smfi_main() == MI_FAILURE) {
    fprintf(stderr, "%s: milter failed\n", SRS_MILTER_NAME);
    exit(EXIT_FAILURE);
  }

  syslog(LOG_INFO, "exitting");
  closelog();
  exit(EXIT_SUCCESS);
}
