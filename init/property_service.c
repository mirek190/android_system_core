/*
 * Copyright (C) 2007 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdarg.h>
#include <dirent.h>
#include <limits.h>
#include <errno.h>

#include <cutils/misc.h>
#include <cutils/sockets.h>

#define _REALLY_INCLUDE_SYS__SYSTEM_PROPERTIES_H_
#include <sys/_system_properties.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/mman.h>
#include <sys/atomics.h>
#include <private/android_filesystem_config.h>

#ifdef HAVE_SELINUX
#include <selinux/selinux.h>
#include <selinux/label.h>
#endif

#include "property_service.h"
#include "init.h"
#include "util.h"
#include "log.h"

#include <device_perms.h>

#define PERSISTENT_PROPERTY_DIR  "/data/property"

static int persistent_properties_loaded = 0;
static int property_area_inited = 0;

static int property_set_fd = -1;

/* White list of permissions for setting property services. */
#ifndef PROPERTY_PERMS
struct {
    const char *prefix;
    unsigned int uid;
    unsigned int gid;
} property_perms[] = {
    { "net.caif0.",       AID_RADIO,    0 },
    { "net.usb0.",        AID_RADIO,    0 },
    { "net.usb1.",        AID_RADIO,    0 },
    { "net.qmi0.",        AID_RADIO,    0 },
    { "net.qmi1.",        AID_RADIO,    0 },
    { "net.qmi2.",        AID_RADIO,    0 },
    { "net.rmnet",        AID_RADIO,    0 },
    { "net.rmnet0.",      AID_RADIO,    0 },
    { "net.gannet0.",     AID_RADIO,    0 },
    { "net.gprs.",        AID_RADIO,    0 },
    { "net.ppp",          AID_RADIO,    0 },
    { "net.qmi",          AID_RADIO,    0 },
    { "net.lte",          AID_RADIO,    0 },
    { "net.cdma",         AID_RADIO,    0 },
    { "ril.",             AID_RADIO,    0 },
    { "gsm.",             AID_RADIO,    0 },
    { "persist.radio",    AID_RADIO,    0 },
    { "net.dns",          AID_RADIO,    0 },
    { "net.dns",          AID_DHCP,     0 },
    { "net.dns",          AID_VPN,      0 },
    { "net.vpnclient",    AID_VPN,      0 },
    { "net.dnschange",    AID_VPN,      0 },
    { "serialno",         AID_RADIO,    0 },
    { "radio.",           AID_RADIO,    0 },
    { "sys.usb.config",   AID_RADIO,    0 },
    { "net.",             AID_SYSTEM,   0 },
    { "dev.",             AID_SYSTEM,   0 },
    { "runtime.",         AID_SYSTEM,   0 },
    { "hw.",              AID_SYSTEM,   0 },
    { "sys.",             AID_SYSTEM,   0 },
    { "service.",         AID_SYSTEM,   0 },
    { "service.",         AID_RADIO,    0 },
    { "wlan.",            AID_SYSTEM,   0 },
    { "bluetooth.",       AID_BLUETOOTH,   0 },
    { "hostapd.",         AID_WIFI,     0 },
    { "dhcp.",            AID_SYSTEM,   0 },
    { "dhcp.",            AID_DHCP,     0 },
    { "debug.nfc.",       AID_NFC,      0 }, // rjones1, 6/25/2012, IKMAIN-46254
    { "debug.",           AID_SYSTEM,   0 },
    { "debug.",           AID_SHELL,    0 },
    { "log.",             AID_SHELL,    AID_LOG },
    { "service.adb.root", AID_SHELL,    0 },
    { "service.adb.tcp.port", AID_SHELL,    0 },
    { "persist.mmac.", AID_SYSTEM, 0 },
    { "persist.sys.",     AID_SYSTEM,   0 },
    { "persist.service.", AID_SYSTEM,   AID_RADIO },
    { "persist.security.", AID_SYSTEM,   0 },
    { "persist.log.",     AID_SHELL,    AID_LOG },
    { "persist.tcmd.", AID_MOT_TCMD,   0 },
    { "tcmd.",            AID_MOT_TCMD, AID_MOT_WHISPER },
    { "persist.mot.proximity.", AID_RADIO, 0},
    { "mot.backup_restore.",AID_MOT_TCMD, 0},
    { "mot.",             AID_MOT_TCMD, 0 },
    { "sys.",             AID_MOT_OSH,  0 },
    { "hw.",              AID_MOT_OSH,  0 },
    { "cdma.nbpcd.supported", AID_RADIO, AID_RADIO },
    { "hw.",              AID_MOT_WHISPER, 0 },
    { "lte.default.protocol",      AID_RADIO,    0 },
    { "lte.ignoredns",             AID_RADIO,    0 },
    { "vzw.inactivetimer",         AID_RADIO,    0 },
    { "android.telephony.apn-restore", AID_RADIO,    0 },
    { "hw.",              AID_MEDIA,   0 },
    { "persist.ril.event.report", AID_RADIO, 0 },
    { "persist.atvc.",    AID_MOT_ATVC,  0 },
    { "persist.service.bdroid.", AID_BLUETOOTH,   0 },
    { "selinux."         , AID_SYSTEM,   0 },
    { "net.pdp",          AID_RADIO,    AID_RADIO },
    { "service.bootanim.exit", AID_GRAPHICS, 0 },
#ifdef PROPERTY_PERMS_APPEND
PROPERTY_PERMS_APPEND
#endif
    { NULL, 0, 0 }
};
/* Avoid extending this array. Check device_perms.h */
#endif

/*
 * White list of UID that are allowed to start/stop services.
 * Currently there are no user apps that require.
 */
#ifndef CONTROL_PERMS
struct {
    const char *service;
    unsigned int uid;
    unsigned int gid;
} control_perms[] = {
    { "dumpstate",AID_SHELL, AID_LOG },
    { "bug2go-bugreport", AID_LOG, AID_LOG},
    { "ril-daemon",AID_RADIO, AID_RADIO },
    { "hciattach", AID_MOT_TCMD, AID_MOT_TCMD },
    { "bluetoothd",AID_MOT_TCMD, AID_MOT_TCMD },
    { "bt_start", AID_MOT_TCMD, AID_MOT_TCMD },
    { "bt_stop", AID_MOT_TCMD, AID_MOT_TCMD },
    { "whisperd", AID_MOT_TCMD, AID_MOT_TCMD },
    { "gadget-lte-modem", AID_RADIO, AID_RADIO },
    { "gadget-qbp-modem", AID_RADIO, AID_RADIO },
    { "gadget-qbp-diag", AID_RADIO, AID_RADIO },
    { "ftmipcd", AID_RADIO, AID_RADIO },
    { "mdm_usb_suspend", AID_RADIO, AID_RADIO },
    { "pcsc",AID_WIFI, AID_WIFI },  /* Allow wpa_supplicant to start the pcsc-lite daemon used for EAP-SIM/AKA auth */
    { "uim",AID_BLUETOOTH, AID_BLUETOOTH },
#ifdef CONTROL_PERMS_APPEND
CONTROL_PERMS_APPEND
#endif
     {NULL, 0, 0 }
};
/* Avoid extending this array. Check device_perms.h */
#endif

typedef struct {
    void *data;
    size_t size;
    int fd;
} workspace;

static int init_workspace(workspace *w, size_t size)
{
    void *data;
    int fd;

        /* dev is a tmpfs that we can use to carve a shared workspace
         * out of, so let's do that...
         */
    fd = open("/dev/__properties__", O_RDWR | O_CREAT | O_NOFOLLOW, 0600);
    if (fd < 0)
        return -1;

    if (ftruncate(fd, size) < 0)
        goto out;

    data = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if(data == MAP_FAILED)
        goto out;

    close(fd);

    fd = open("/dev/__properties__", O_RDONLY | O_NOFOLLOW);
    if (fd < 0)
        return -1;

    unlink("/dev/__properties__");

    w->data = data;
    w->size = size;
    w->fd = fd;
    return 0;

out:
    close(fd);
    return -1;
}

/* PA_COUNT_MAX formula:
 * PA_COUNT_MAX * 128 + PA_COUNT_MAX * 4 + 32 + 4 <= Allocation memory
 * Where:
 *     Allocate memory = 17 * 4096 = 69632 bytes
 * PA_COUNT_MAX = 527
 */
#define PA_COUNT_MAX   527
/* PA_INFO_START = 8 header words(32 bytes)
 *               + 527 toc words(2108 bytes)
 *               + 4 bytes
 *               = 2144 bytes
 */
#define PA_INFO_START  2144
#define PA_SIZE        69632

static workspace pa_workspace;
static prop_info *pa_info_array;

extern prop_area *__system_property_area__;

static int init_property_area(void)
{
    prop_area *pa;

    if(pa_info_array)
        return -1;

    if(init_workspace(&pa_workspace, PA_SIZE))
        return -1;

    fcntl(pa_workspace.fd, F_SETFD, FD_CLOEXEC);

    pa_info_array = (void*) (((char*) pa_workspace.data) + PA_INFO_START);

    pa = pa_workspace.data;
    memset(pa, 0, PA_SIZE);
    pa->magic = PROP_AREA_MAGIC;
    pa->version = PROP_AREA_VERSION;

        /* plug into the lib property services */
    __system_property_area__ = pa;
    property_area_inited = 1;
    return 0;
}

static void update_prop_info(prop_info *pi, const char *value, unsigned len)
{
    pi->serial = pi->serial | 1;
    memcpy(pi->value, value, len + 1);
    pi->serial = (len << 24) | ((pi->serial + 1) & 0xffffff);
    __futex_wake(&pi->serial, INT32_MAX);
}

static int check_mac_perms(const char *name, char *sctx)
{
#ifdef HAVE_SELINUX
    if (is_selinux_enabled() <= 0)
        return 1;

    char *tctx = NULL;
    const char *class = "property_service";
    const char *perm = "set";
    int result = 0;

    if (!sctx)
        goto err;

    if (!sehandle_prop)
        goto err;

    if (selabel_lookup(sehandle_prop, &tctx, name, 1) != 0)
        goto err;

    if (selinux_check_access(sctx, tctx, class, perm, name) == 0)
        result = 1;

    freecon(tctx);
 err:
    return result;

#endif
    return 1;
}

static int check_control_mac_perms(const char *name, char *sctx)
{
#ifdef HAVE_SELINUX

    /*
     *  Create a name prefix out of ctl.<service name>
     *  The new prefix allows the use of the existing
     *  property service backend labeling while avoiding
     *  mislabels based on true property prefixes.
     */
    char ctl_name[PROP_VALUE_MAX+4];
    int ret = snprintf(ctl_name, sizeof(ctl_name), "ctl.%s", name);

    if (ret < 0 || (size_t) ret >= sizeof(ctl_name))
        return 0;

    return check_mac_perms(ctl_name, sctx);

#endif
    return 1;
}

/*
 * Checks permissions for starting/stoping system services.
 * AID_SYSTEM and AID_ROOT are always allowed.
 *
 * Returns 1 if uid allowed, 0 otherwise.
 */
static int check_control_perms(const char *name, unsigned int uid, unsigned int gid, char *sctx) {

    int i;
    if (uid == AID_SYSTEM || uid == AID_ROOT)
      return check_control_mac_perms(name, sctx);

    /* Search the ACL */
    for (i = 0; control_perms[i].service; i++) {
        if (strcmp(control_perms[i].service, name) == 0) {
            if ((uid && control_perms[i].uid == uid) ||
                (gid && control_perms[i].gid == gid)) {
                return check_control_mac_perms(name, sctx);
            }
        }
    }

    if (strncmp(name, "uim:", 4) == 0) {
        if ((uid == AID_BLUETOOTH) ||
            (gid == AID_BLUETOOTH)) {
                return 1;
        }
    }
    return 0;
}

/*
 * Checks permissions for setting system properties.
 * Returns 1 if uid allowed, 0 otherwise.
 */
static int check_perms(const char *name, unsigned int uid, unsigned int gid, char *sctx)
{
    int i;
    if(!strncmp(name, "ro.", 3))
        name +=3;

    if (uid == 0)
        return check_mac_perms(name, sctx);

    for (i = 0; property_perms[i].prefix; i++) {
        if (strncmp(property_perms[i].prefix, name,
                    strlen(property_perms[i].prefix)) == 0) {
            if ((uid && property_perms[i].uid == uid) ||
                (gid && property_perms[i].gid == gid)) {

                return check_mac_perms(name, sctx);
            }
        }
    }

    return 0;
}

const char* property_get(const char *name)
{
    prop_info *pi;

    if(strlen(name) >= PROP_NAME_MAX) return 0;

    pi = (prop_info*) __system_property_find(name);

    if(pi != 0) {
        return pi->value;
    } else {
        return 0;
    }
}

static void write_persistent_property(const char *name, const char *value)
{
    const char *tempPath = PERSISTENT_PROPERTY_DIR "/.temp";
    char path[PATH_MAX];
    int fd, length;

    snprintf(path, sizeof(path), "%s/%s", PERSISTENT_PROPERTY_DIR, name);

    fd = open(tempPath, O_WRONLY|O_CREAT|O_TRUNC, 0600);
    if (fd < 0) {
        ERROR("Unable to write persistent property to temp file %s errno: %d\n", tempPath, errno);
        return;
    }
    write(fd, value, strlen(value));
    close(fd);

    snprintf(path, sizeof(path), "%s/%s", PERSISTENT_PROPERTY_DIR, name);
    if (rename(tempPath, path)) {
        unlink(tempPath);
        ERROR("Unable to rename persistent property file %s to %s\n", tempPath, path);
    }
}

int property_set(const char *name, const char *value)
{
    prop_area *pa;
    prop_info *pi;

    size_t namelen = strlen(name);
    size_t valuelen = strlen(value);

    if(namelen >= PROP_NAME_MAX) return -1;
    if(valuelen >= PROP_VALUE_MAX) return -1;
    if(namelen < 1) return -1;

    pi = (prop_info*) __system_property_find(name);

    if(pi != 0) {
        /* ro.* properties may NEVER be modified once set */
        if(!strncmp(name, "ro.", 3)) return -1;

        pa = __system_property_area__;
        update_prop_info(pi, value, valuelen);
        pa->serial++;
        __futex_wake(&pa->serial, INT32_MAX);
    } else {
        pa = __system_property_area__;
        if(pa->count == PA_COUNT_MAX) return -1;

        pi = pa_info_array + pa->count;
        pi->serial = (valuelen << 24);
        memcpy(pi->name, name, namelen + 1);
        memcpy(pi->value, value, valuelen + 1);

        pa->toc[pa->count] =
            (namelen << 24) | (((unsigned) pi) - ((unsigned) pa));

        pa->count++;
        pa->serial++;
        __futex_wake(&pa->serial, INT32_MAX);
    }
    /* If name starts with "net." treat as a DNS property. */
    if (strncmp("net.", name, strlen("net.")) == 0)  {
        if (strcmp("net.change", name) == 0) {
            return 0;
        }
       /*
        * The 'net.change' property is a special property used track when any
        * 'net.*' property name is updated. It is _ONLY_ updated here. Its value
        * contains the last updated 'net.*' property.
        */
        property_set("net.change", name);
    } else if (persistent_properties_loaded &&
            strncmp("persist.", name, strlen("persist.")) == 0) {
        /*
         * Don't write properties to disk until after we have read all default properties
         * to prevent them from being overwritten by default values.
         */
        write_persistent_property(name, value);
#ifdef HAVE_SELINUX
    } else if (strcmp("selinux.reload_policy", name) == 0 &&
               strcmp("1", value) == 0) {
        selinux_reload_policy();
#endif
    }
    property_changed(name, value);
    return 0;
}

void handle_property_set_fd()
{
    prop_msg msg;
    int s;
    int r;
    int res;
    struct ucred cr;
    struct sockaddr_un addr;
    socklen_t addr_size = sizeof(addr);
    socklen_t cr_size = sizeof(cr);
    char * source_ctx = NULL;

    if ((s = accept(property_set_fd, (struct sockaddr *) &addr, &addr_size)) < 0) {
        return;
    }

    /* Check socket options here */
    if (getsockopt(s, SOL_SOCKET, SO_PEERCRED, &cr, &cr_size) < 0) {
        close(s);
        ERROR("Unable to receive socket options\n");
        return;
    }

    r = TEMP_FAILURE_RETRY(recv(s, &msg, sizeof(msg), 0));
    if(r != sizeof(prop_msg)) {
        ERROR("sys_prop: mis-match msg size received: %d expected: %d errno: %d\n",
              r, sizeof(prop_msg), errno);
        close(s);
        return;
    }

    switch(msg.cmd) {
    case PROP_MSG_SETPROP:
        msg.name[PROP_NAME_MAX-1] = 0;
        msg.value[PROP_VALUE_MAX-1] = 0;

#ifdef HAVE_SELINUX
        getpeercon(s, &source_ctx);
#endif

        if(memcmp(msg.name,"ctl.",4) == 0) {
            // Keep the old close-socket-early behavior when handling
            // ctl.* properties.
            close(s);
            if (check_control_perms(msg.value, cr.uid, cr.gid, source_ctx)) {
                handle_control_message((char*) msg.name + 4, (char*) msg.value);
            } else {
                ERROR("sys_prop: Unable to %s service ctl [%s] uid:%d gid:%d pid:%d\n",
                        msg.name + 4, msg.value, cr.uid, cr.gid, cr.pid);
            }
        } else {
            if (check_perms(msg.name, cr.uid, cr.gid, source_ctx)) {
                property_set((char*) msg.name, (char*) msg.value);
            } else {
                ERROR("sys_prop: permission denied uid:%d  name:%s\n",
                      cr.uid, msg.name);
            }

            // Note: bionic's property client code assumes that the
            // property server will not close the socket until *AFTER*
            // the property is written to memory.
            close(s);
        }
#ifdef HAVE_SELINUX
        freecon(source_ctx);
#endif

        break;

    default:
        close(s);
        break;
    }
}

void get_property_workspace(int *fd, int *sz)
{
    *fd = pa_workspace.fd;
    *sz = pa_workspace.size;
}

static void load_properties(char *data)
{
    char *key, *value, *eol, *sol, *tmp;

    sol = data;
    while((eol = strchr(sol, '\n'))) {
        key = sol;
        *eol++ = 0;
        sol = eol;

        value = strchr(key, '=');
        if(value == 0) continue;
        *value++ = 0;

        while(isspace(*key)) key++;
        if(*key == '#') continue;
        tmp = value - 2;
        while((tmp > key) && isspace(*tmp)) *tmp-- = 0;

        while(isspace(*value)) value++;
        tmp = eol - 2;
        while((tmp > value) && isspace(*tmp)) *tmp-- = 0;

        property_set(key, value);
    }
}

static void load_properties_from_file(const char *fn)
{
    char *data;
    unsigned sz;

    data = read_file(fn, &sz);

    if(data != 0) {
        load_properties(data);
        free(data);
    }
}

static void load_persistent_properties()
{
    DIR* dir = opendir(PERSISTENT_PROPERTY_DIR);
    int dir_fd;
    struct dirent*  entry;
    char value[PROP_VALUE_MAX];
    int fd, length;
    struct stat sb;

    if (dir) {
        dir_fd = dirfd(dir);
        while ((entry = readdir(dir)) != NULL) {
            if (strncmp("persist.", entry->d_name, strlen("persist.")))
                continue;
#if HAVE_DIRENT_D_TYPE
            if (entry->d_type != DT_REG)
                continue;
#endif
            /* open the file and read the property value */
            fd = openat(dir_fd, entry->d_name, O_RDONLY | O_NOFOLLOW);
            if (fd < 0) {
                ERROR("Unable to open persistent property file \"%s\" errno: %d\n",
                      entry->d_name, errno);
                continue;
            }
            if (fstat(fd, &sb) < 0) {
                ERROR("fstat on property file \"%s\" failed errno: %d\n", entry->d_name, errno);
                close(fd);
                continue;
            }

            // File must not be accessible to others, be owned by root/root, and
            // not be a hard link to any other file.
            if (((sb.st_mode & (S_IRWXG | S_IRWXO)) != 0)
                    || (sb.st_uid != 0)
                    || (sb.st_gid != 0)
                    || (sb.st_nlink != 1)) {
                ERROR("skipping insecure property file %s (uid=%lu gid=%lu nlink=%d mode=%o)\n",
                      entry->d_name, sb.st_uid, sb.st_gid, sb.st_nlink, sb.st_mode);
                close(fd);
                continue;
            }

            length = read(fd, value, sizeof(value) - 1);
            if (length >= 0) {
                value[length] = 0;
                property_set(entry->d_name, value);
            } else {
                ERROR("Unable to read persistent property file %s errno: %d\n",
                      entry->d_name, errno);
            }
            close(fd);
        }
        closedir(dir);
    } else {
        ERROR("Unable to open persistent property directory %s errno: %d\n", PERSISTENT_PROPERTY_DIR, errno);
    }

    persistent_properties_loaded = 1;
}

void property_init(void)
{
    init_property_area();
}

void property_load_boot_defaults(void)
{
    load_properties_from_file(PROP_PATH_RAMDISK_DEFAULT);
}

int properties_inited(void)
{
    return property_area_inited;
}

static void load_override_properties() {
#ifdef ALLOW_LOCAL_PROP_OVERRIDE
    const char *debuggable = property_get("ro.debuggable");
    if (debuggable && (strcmp(debuggable, "1") == 0)) {
        load_properties_from_file(PROP_PATH_LOCAL_OVERRIDE);
    }
#endif /* ALLOW_LOCAL_PROP_OVERRIDE */
}


/* When booting an encrypted system, /data is not mounted when the
 * property service is started, so any properties stored there are
 * not loaded.  Vold triggers init to load these properties once it
 * has mounted /data.
 */
void load_persist_props(void)
{
    load_override_properties();
    /* Read persistent properties after all default values have been loaded. */
    load_persistent_properties();
}

/* BEGIN Motorola, Darren Shu - w36016, July 31,2012, IKSECURITY-199 */
/* This provides backwards compatibility with for the read only services
   which were once used by the applications using the access token feature. */
void update_legacy_atvc_properties(void)
{
    char *atvc_property_value;
    atvc_property_value = property_get("persist.atvc.simswap");

    if (atvc_property_value != NULL)    {
        property_set("ro.sys.atvc_allow_simswap", atvc_property_value);
    }
    else    {
        property_set("ro.sys.atvc_allow_simswap", "0");
        property_set("ro.sys.atvc_efem", "0");
    }
    atvc_property_value = property_get("persist.atvc.log");
    if (atvc_property_value != NULL)    {
        property_set("ro.sys.atvc_allow_bp_log", atvc_property_value);
        property_set("ro.sys.atvc_allow_ap_mot_log", atvc_property_value);
        property_set("ro.sys.atvc_allow_gki_log", atvc_property_value);
    }
    else    {
        property_set("ro.sys.atvc_allow_bp_log", "0");
        property_set("ro.sys.atvc_allow_ap_mot_log", "0");
        property_set("ro.sys.atvc_allow_gki_log", "0");
    }

    atvc_property_value = property_get("persist.atvc.netmon_usb");
    if (atvc_property_value != NULL)    {
        property_set("ro.sys.atvc_allow_netmon_usb", atvc_property_value);
    }
    else    {
        property_set("ro.sys.atvc_allow_netmon_usb", "0");
    }

    atvc_property_value = property_get("persist.atvc.netmon_ih");
    if (atvc_property_value != NULL)    {
        property_set("ro.sys.atvc_allow_netmon_ih", atvc_property_value);
    }
    else    {
        property_set("ro.sys.atvc_allow_netmon_ih", "0");
    }

    atvc_property_value = property_get("persist.atvc.allow_res_core");
    if (atvc_property_value != NULL)    {
        property_set("ro.sys.atvc_allow_res_core", atvc_property_value);
    }
    else    {
        property_set("ro.sys.atvc_allow_res_core", "0");
    }

    atvc_property_value = property_get("persist.atvc.allow_res_panic");
    if (atvc_property_value != NULL)    {
        property_set("ro.sys.atvc_allow_res_panic", atvc_property_value);
    }
    else    {
        property_set("ro.sys.atvc_allow_res_panic", "0");
    }
    atvc_property_value = property_get("persist.atvc.allow_all_core");
    if (atvc_property_value != NULL)    {
        property_set("ro.sys.atvc_allow_all_core", atvc_property_value);
    }
    else    {
        property_set("ro.sys.atvc_allow_all_core", "0");
    }
}
/* END IKSECURITY-199 */

void start_property_service(void)
{
    int fd;

    load_properties_from_file(PROP_PATH_SYSTEM_BUILD);
    load_properties_from_file(PROP_PATH_SYSTEM_DEFAULT);
    load_override_properties();
    /* Read persistent properties after all default values have been loaded. */
    load_persistent_properties();

    update_legacy_atvc_properties();

    fd = create_socket(PROP_SERVICE_NAME, SOCK_STREAM, 0666, 0, 0, NULL);
    if(fd < 0) return;
    fcntl(fd, F_SETFD, FD_CLOEXEC);
    fcntl(fd, F_SETFL, O_NONBLOCK);

    listen(fd, 8);
    property_set_fd = fd;
}

int get_property_set_fd()
{
    return property_set_fd;
}
